from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_BOUND"
CONTRACT_OUTCOME = "POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_DEFINED__AUTHORITATIVE_DERIVATION_ONLY"
NEXT_MOVE = "AUTHOR_POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_PACKET"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


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


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _git_merge_base(root: Path, left: str, right: str) -> str:
    result = subprocess.run(
        ["git", "merge-base", left, right],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _source_precedence(root: Path) -> List[Dict[str, Any]]:
    return [
        {
            "rank": 1,
            "class_id": "canonical_post_merge_repo_authority",
            "drives_live_truth": True,
            "refs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.json").as_posix(),
            ],
            "rule": "Canonical post-merge repo authority outranks every branch-local, package-local, historical, or prep-only surface.",
        },
        {
            "rank": 2,
            "class_id": "canonical_theorem_and_product_truth",
            "drives_live_truth": True,
            "refs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_gate_d_post_clear_branch_law_packet.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_final_summary_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json").as_posix(),
            ],
            "rule": "Canonical theorem/product receipts define live posture after merge unless a later canonical supersession receipt says otherwise.",
        },
        {
            "rank": 3,
            "class_id": "authoritative_successor_lane_packets",
            "drives_live_truth": True,
            "refs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json").as_posix(),
            ],
            "rule": "Authoritative successor-lane packets may extend derivation law but may not weaken canonical post-merge truth already frozen on main.",
        },
        {
            "rank": 4,
            "class_id": "historical_and_superseded_lineage",
            "drives_live_truth": False,
            "refs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/truth_supersession_rules.json").as_posix(),
            ],
            "rule": "Historical and superseded surfaces may explain lineage, but they may never override current canonical truth.",
        },
        {
            "rank": 5,
            "class_id": "deferred_package_and_non_authoritative_prep",
            "drives_live_truth": False,
            "refs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_residual_proof_law_hardening_packet.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_upper_stack_ratification_scope_packet.json").as_posix(),
                common.resolve_path(
                    root,
                    "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/scripts/stage_and_promote.sh",
                ).as_posix(),
            ],
            "rule": "Deferred package artifacts and prep-only lanes cannot drive live truth until separately promoted by an explicit later court.",
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    main_head: str,
    authority_packet: Dict[str, Any],
    post_merge_snapshot: Dict[str, Any],
    post_merge_receipt: Dict[str, Any],
    legacy_truth_contract: Dict[str, Any],
    posture_contract: Dict[str, Any],
    settled_truth_contract: Dict[str, Any],
    supersession_rules: Dict[str, Any],
    reporting_integrity_contract: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    precedence = _source_precedence(root)
    retained_prep = list(post_merge_snapshot.get("retained_non_authoritative_prep_lanes", []))
    package_split = dict(post_merge_snapshot.get("package_promotion_split", {}))
    authority_scope = dict(authority_packet.get("authoritative_scope", {}))

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_validator_contract_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "claim_boundary": (
            "This contract binds only mechanical truth derivation and contradiction handling for post-merge KT authority. "
            "It is not a general cleanup lane, does not perform package promotion, and does not widen theorem or product claims."
        ),
        "authority_header": {
            "canonical_authority_branch": "main",
            "authoritative_lane_branch": branch_name,
            "authoritative_lane_branch_head": branch_head,
            "canonical_parent_main_head": main_head,
            "package_promotion_still_deferred": bool(post_merge_receipt.get("package_promotion_still_deferred", False)),
            "track03_repo_authority_now_canonical": bool(post_merge_receipt.get("track03_repo_authority_now_canonical", False)),
        },
        "source_precedence": precedence,
        "posture_enum_contract": {
            "theorem_truth": [
                "GATE_D_CLEARED__SUCCESSOR_LINE",
                "GATE_E_OPEN__SUCCESSOR_LINE",
                "THEOREM_POSTURE_CANONICAL_ON_MAIN",
            ],
            "product_truth": [
                "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY",
                "PRODUCT_POSTURE_CANONICAL_ON_MAIN",
                "PRODUCT_POSTURE_STILL_BOUNDED",
            ],
            "merge_truth": [
                "TRACK03_REPO_AUTHORITY_BRANCH_ONLY",
                "TRACK03_REPO_AUTHORITY_CANONICAL_ON_MAIN",
                "TRACK03_PROTECTED_PR_PENDING",
            ],
            "package_truth": [
                "PACKAGE_PROMOTION_DEFERRED",
                "PACKAGE_PROMOTION_PARTIALLY_AUTHORIZED",
                "PACKAGE_PROMOTION_CANONICALIZED",
            ],
        },
        "contradiction_classes": [
            {"class_id": "stale_vs_live", "summary": "A stale receipt or packet claims a stronger or different posture than the current canonical live surface."},
            {"class_id": "historical_vs_superseded", "summary": "A historical checkpoint attempts to outrank an explicit supersession or newer canonical receipt."},
            {"class_id": "package_vs_repo", "summary": "A deferred package artifact attempts to drive canonical repo truth."},
            {"class_id": "branch_local_vs_canonical", "summary": "A branch-local receipt or packet outranks canonical main-level authority."},
            {"class_id": "theorem_vs_product", "summary": "Theorem posture and product posture surfaces imply incompatible live states."},
            {"class_id": "prep_lane_overreach", "summary": "A non-authoritative prep lane publishes or implies live authority."},
            {"class_id": "missing_authority_source", "summary": "A derived output cannot name the authoritative source that justified it."},
        ],
        "derivation_law": {
            "inputs": {
                "required_canonical_inputs": [
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
                ],
                "required_governance_inputs": [
                    common.resolve_path(root, "KT_PROD_CLEANROOM/governance/truth_engine_contract.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/governance/posture_contract.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/governance/truth_supersession_rules.json").as_posix(),
                    common.resolve_path(root, "KT_PROD_CLEANROOM/reports/reporting_integrity_contract.json").as_posix(),
                ],
            },
            "precedence_rule": "Lowest numeric rank in source_precedence wins; non-driving classes can explain but cannot determine output posture.",
            "tie_break_rule": "If two driving sources of equal rank disagree, fail closed and emit a contradiction ledger instead of updating live posture.",
            "fail_closed_rule": "Missing required canonical inputs, missing source provenance, or package/prep overreach halts recomputation.",
            "output_rule": "Every emitted posture or contradiction artifact must name the winning source and every rejected conflicting source.",
        },
        "exclusion_law": {
            "never_drive_live_truth": [
                "deferred package files",
                "superseded historical checkpoints",
                "non-authoritative prep lanes",
                "smoke-only artifacts",
                "branch-local packets that have not crossed the authority rule",
            ],
            "package_boundary_preserved": {
                "package_promotion_boundary": str(package_split.get("package_promotion_boundary", "")).strip(),
                "package_auto_promotion_candidate_count": int(package_split.get("auto_promotion_candidate_count", 0)),
                "review_approved_auto_skip_count": int(package_split.get("review_approved_auto_skip_count", 0)),
                "review_approved_out_of_scope_count": int(package_split.get("review_approved_out_of_scope_count", 0)),
            },
            "retained_non_authoritative_prep_lanes": retained_prep,
        },
        "emission_surfaces": {
            "authority_graph": "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_authority_graph.json",
            "posture_index": "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
            "contradiction_ledger": "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_ledger.json",
            "stale_source_quarantine_list": "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_stale_source_quarantine_list.json",
            "authoritative_recompute_receipt": "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
        },
        "failure_law": {
            "halt_recomputation_when": [
                "required canonical source is missing",
                "two driving sources of equal rank disagree",
                "package or prep surface attempts to drive live truth",
                "source provenance cannot be attached to emitted posture",
            ],
            "warn_only_when": [
                "historical lineage surface is stale but already non-driving",
                "excluded prep surface changed without attempting posture override",
            ],
            "new_court_required_when": [
                "theorem and product truths would need simultaneous reinterpretation",
                "package promotion boundary must change",
                "source precedence ranking itself must be modified",
            ],
        },
        "supporting_contracts": {
            "legacy_truth_engine_contract_id": str(legacy_truth_contract.get("contract_id", "")).strip(),
            "posture_contract_id": str(posture_contract.get("contract_id", "")).strip(),
            "settled_truth_source_contract_id": str(settled_truth_contract.get("contract_id", "")).strip(),
            "truth_supersession_rules_id": str(supersession_rules.get("rules_id", "")).strip(),
            "reporting_integrity_contract_id": str(reporting_integrity_contract.get("contract_id", "")).strip(),
        },
        "authoritative_scope_carried_forward": authority_scope,
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "contract_outcome": CONTRACT_OUTCOME,
        "source_precedence_class_count": len(precedence),
        "contradiction_class_count": len(packet["contradiction_classes"]),
        "posture_enum_domain_count": len(packet["posture_enum_contract"]),
        "emission_surface_count": len(packet["emission_surfaces"]),
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Truth Engine Contradiction Validator Contract Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Contract outcome: `{CONTRACT_OUTCOME}`",
            f"- Source precedence classes: `{len(precedence)}`",
            f"- Contradiction classes: `{len(packet['contradiction_classes'])}`",
            f"- Posture enum domains: `{len(packet['posture_enum_contract'])}`",
            f"- Emission surfaces: `{len(packet['emission_surfaces'])}`",
            "- Package promotion remains explicitly excluded from live truth derivation.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    post_merge_snapshot_path: Path,
    post_merge_receipt_path: Path,
    legacy_truth_contract_path: Path,
    posture_contract_path: Path,
    settled_truth_contract_path: Path,
    supersession_rules_path: Path,
    reporting_integrity_contract_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: truth-engine contract packet must run on {REQUIRED_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: truth-engine contract packet requires a clean worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="truth-engine authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="truth-engine authority receipt")
    post_merge_snapshot = common.load_json_required(root, post_merge_snapshot_path, label="Track 03 post-merge branch snapshot")
    post_merge_receipt = common.load_json_required(root, post_merge_receipt_path, label="Track 03 post-merge closeout receipt")
    legacy_truth_contract = common.load_json_required(root, legacy_truth_contract_path, label="legacy truth engine contract")
    posture_contract = common.load_json_required(root, posture_contract_path, label="posture contract")
    settled_truth_contract = common.load_json_required(root, settled_truth_contract_path, label="settled truth source contract")
    supersession_rules = common.load_json_required(root, supersession_rules_path, label="truth supersession rules")
    reporting_integrity_contract = common.load_json_required(root, reporting_integrity_contract_path, label="reporting integrity contract")

    common.ensure_pass(authority_packet, label="truth-engine authority packet")
    common.ensure_pass(authority_receipt, label="truth-engine authority receipt")
    common.ensure_pass(post_merge_receipt, label="Track 03 post-merge closeout receipt")

    if str(authority_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_PACKET":
        raise RuntimeError("FAIL_CLOSED: authority packet does not authorize the truth-engine contract packet")
    if str(authority_receipt.get("lane_outcome", "")).strip() != "POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_LANE_OPEN__AUTHORITATIVE_ONLY":
        raise RuntimeError("FAIL_CLOSED: truth-engine authoritative lane is not open")
    if not bool(post_merge_receipt.get("package_promotion_still_deferred", False)):
        raise RuntimeError("FAIL_CLOSED: package promotion boundary must still be deferred")

    main_head = _git_rev_parse(root, "main")
    if _git_merge_base(root, "main", "HEAD") != main_head:
        raise RuntimeError("FAIL_CLOSED: truth-engine contract branch must remain based on current main without divergence")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        main_head=main_head,
        authority_packet=authority_packet,
        post_merge_snapshot=post_merge_snapshot,
        post_merge_receipt=post_merge_receipt,
        legacy_truth_contract=legacy_truth_contract,
        posture_contract=posture_contract,
        settled_truth_contract=settled_truth_contract,
        supersession_rules=supersession_rules,
        reporting_integrity_contract=reporting_integrity_contract,
    )

    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "contract_outcome": CONTRACT_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the post-F truth-engine contradiction-validator contract packet.")
    parser.add_argument(
        "--authority-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
    )
    parser.add_argument(
        "--authority-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json",
    )
    parser.add_argument(
        "--post-merge-snapshot",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json",
    )
    parser.add_argument(
        "--post-merge-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json",
    )
    parser.add_argument(
        "--legacy-truth-contract",
        default="KT_PROD_CLEANROOM/governance/truth_engine_contract.json",
    )
    parser.add_argument(
        "--posture-contract",
        default="KT_PROD_CLEANROOM/governance/posture_contract.json",
    )
    parser.add_argument(
        "--settled-truth-contract",
        default="KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json",
    )
    parser.add_argument(
        "--supersession-rules",
        default="KT_PROD_CLEANROOM/governance/truth_supersession_rules.json",
    )
    parser.add_argument(
        "--reporting-integrity-contract",
        default="KT_PROD_CLEANROOM/reports/reporting_integrity_contract.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        post_merge_snapshot_path=common.resolve_path(root, args.post_merge_snapshot),
        post_merge_receipt_path=common.resolve_path(root, args.post_merge_receipt),
        legacy_truth_contract_path=common.resolve_path(root, args.legacy_truth_contract),
        posture_contract_path=common.resolve_path(root, args.posture_contract),
        settled_truth_contract_path=common.resolve_path(root, args.settled_truth_contract),
        supersession_rules_path=common.resolve_path(root, args.supersession_rules),
        reporting_integrity_contract_path=common.resolve_path(root, args.reporting_integrity_contract),
    )
    print(result["contract_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
