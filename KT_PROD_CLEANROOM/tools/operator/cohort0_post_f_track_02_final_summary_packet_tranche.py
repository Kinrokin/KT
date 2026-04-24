from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_02_dual_audit_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_post_f_track_02_frozen_baseline_and_current_truth_audits_tranche as audit_tranche
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_02_final_summary_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_02_final_summary_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_02_FINAL_SUMMARY_REPORT.md"

EXECUTION_STATUS = "PASS__TRACK_02_FINAL_SUMMARY_PACKET_BOUND"
SUMMARY_OUTCOME = "POST_F_TRACK_02_DUAL_AUDIT_FROZEN__ENGLISH_EXECUTIVE_BRIEF_BOUND"
TRACK_ID = scope_tranche.TRACK_ID
NEXT_MOVE = "AUTHOR_POST_F_TRACK_03_SCOPE_PACKET"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
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


def _scope_score(current_packet: Dict[str, Any], scope_key: str) -> str:
    return str(current_packet["section_2_six_scope_scorecards"][scope_key]["score"]).strip()


def build_outputs(
    *,
    root: Path,
    subject_head: str,
    branch_name: str,
    scope_packet: Dict[str, Any],
    execution_receipt: Dict[str, Any],
    baseline_packet: Dict[str, Any],
    baseline_receipt: Dict[str, Any],
    current_packet: Dict[str, Any],
    current_receipt: Dict[str, Any],
    delta_crosswalk: Dict[str, Any],
    delta_receipt: Dict[str, Any],
    meta_summary: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(scope_packet.get("authority_header", {}))
    current_overrides = dict(current_packet.get("current_truth_overrides_binding", {}))
    current_standing = dict(current_packet.get("section_1_present_standing_reconstruction", {}).get("current_head_standing", {}))
    unresolved_blockers = list(
        current_packet.get("section_1_present_standing_reconstruction", {}).get("unresolved_blockers_preventing_wider_claims", [])
    )
    final_verdict = dict(current_packet.get("section_7_final_verdict", {}))
    benchmark_readiness = dict(current_packet.get("section_9_benchmark_readiness_map", {}))

    english_brief = {
        "baseline_static_ruler": (
            "At the frozen kt-post-f-reaudit-pass anchor, KT had already completed the minimum lawful path through Gate F, "
            "but only as one narrow local verifier wedge. It was a disciplined governed system, not a broad runtime platform or commercially validated product."
        ),
        "current_truth_read": (
            "On the current branch head, KT is still strongest in governance and claim discipline. "
            "Track 01 adds one repeated bounded comparative proof on the confirmed local_verifier_mode wedge, "
            "but broader runtime capability, external ratification, and commercial validation remain blocked."
        ),
        "delta_plain_english": (
            "The main improvement from frozen baseline to current truth is Track 01: KT now has a repeated bounded category-fair advantage on the confirmed wedge. "
            "The structural blockers did not clear; the system is stronger in bounded proof, not broader capability or market validation."
        ),
        "blunt_system_read": (
            "KT is a serious governance-first AI system with one real bounded wedge and one real bounded proof, "
            "but it is still not a broad platform, not broadly capability-ratified, and not commercially proven."
        ),
    }

    explicit_answers = {
        "credible": {
            "answer": True,
            "reason": "The governance spine, receipt chain, and bounded wedge are real and mechanically enforced.",
        },
        "novel": {
            "answer": "bounded_yes",
            "reason": "The strongest novelty is in constitutional governance and authority mechanics, not in broadly proven model capability.",
        },
        "viable": {
            "answer": "bounded_only",
            "reason": "KT is viable today only as a narrow verifier-backed execution and receipt wedge.",
        },
        "marketable": {
            "answer": "cautiously_limited",
            "reason": "It can be positioned narrowly, but there is still no commercial proof, customer proof, or enterprise validation.",
        },
        "frontier_grade": {
            "answer": False,
            "reason": "The audit does not support calling KT a broad frontier runtime or platform system today.",
        },
        "sota": {
            "answer": False,
            "reason": "Track 01 is a bounded wedge comparison, not a broad state-of-the-art result.",
        },
    }

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_final_summary_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "claim_boundary": (
            "This packet freezes Track 02 as a dual-audit summary packet. It preserves the frozen baseline verdict, the hardened current-truth verdict, "
            "and the delta crosswalk without collapsing them into one blended score or widening claims beyond the bounded local_verifier_mode wedge."
        ),
        "track_identity": {
            "track_id": TRACK_ID,
            "track_name": "Post-F Dual Audit",
            "track_status": "CLOSED__DUAL_AUDIT_SUMMARY_PACKET_ONLY",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
        },
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
        },
        "bound_track_stack": {
            "scope_packet_ref": f"KT_PROD_CLEANROOM/reports/{scope_tranche.OUTPUT_PACKET}",
            "shared_harvest_receipt_ref": f"KT_PROD_CLEANROOM/reports/{audit_tranche.harvest_tranche.OUTPUT_RECEIPT}",
            "dual_audit_execution_receipt_ref": f"KT_PROD_CLEANROOM/reports/{audit_tranche.OUTPUT_RECEIPT}",
            "baseline_audit_receipt_ref": f"KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
            "current_truth_audit_receipt_ref": f"KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_current_truth_audit_receipt.json",
            "delta_crosswalk_receipt_ref": f"KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.json",
            "meta_summary_ref": f"KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_meta_summary.json",
        },
        "english_executive_brief": english_brief,
        "baseline_verdict_snapshot": {
            "anchor_commit": str(baseline_receipt.get("anchor_commit", "")).strip(),
            "top_level_verdict": str(meta_summary.get("baseline_audit_reference", {}).get("top_level_verdict", "")).strip(),
            "repo_ruling": str(baseline_packet.get("scope_1_repo_only", {}).get("ruling", "")).strip(),
            "governed_system_ruling": str(baseline_packet.get("scope_2_system_with_receipts", {}).get("ruling", "")).strip(),
            "bounded_target_ruling": str(baseline_packet.get("scope_3_bounded_audited_target", {}).get("ruling", "")).strip(),
            "commercial_ruling": str(baseline_packet.get("scope_4_commercial_product_market_reality", {}).get("ruling", "")).strip(),
        },
        "current_truth_snapshot": {
            "anchor_commit": str(current_receipt.get("anchor_commit", "")).strip(),
            "top_level_verdict": str(current_packet.get("top_level_verdict", "")).strip(),
            "single_sentence_verdict": str(final_verdict.get("single_sentence_verdict", "")).strip(),
            "control_plane_score": _scope_score(current_packet, "scope_1_current_head_sovereign_control_plane"),
            "runtime_score": _scope_score(current_packet, "scope_2_current_head_runtime_capability_plane"),
            "bounded_proof_score": _scope_score(current_packet, "scope_3_historical_bounded_frontier_target"),
            "full_system_score": _scope_score(current_packet, "scope_4_full_system_civilization_execution_readiness"),
            "commercial_score": _scope_score(current_packet, "scope_5_product_commercial_standing"),
            "net_score": _scope_score(current_packet, "scope_6_net_integrated_standing"),
            "current_head_standing": current_standing,
            "current_truth_overrides_binding": current_overrides,
        },
        "delta_snapshot": {
            "preserve_separate_verdicts": bool(delta_crosswalk.get("preserve_separate_verdicts", False)),
            "key_delta_finding": str(meta_summary.get("delta_crosswalk_reference", {}).get("key_delta_finding", "")).strip(),
            "axes_that_improved": list(meta_summary.get("delta_crosswalk_reference", {}).get("axes_that_improved", [])),
            "axes_unchanged": list(meta_summary.get("delta_crosswalk_reference", {}).get("axes_unchanged", [])),
            "axes_maintained_excellent": list(meta_summary.get("delta_crosswalk_reference", {}).get("axes_maintained_excellent", [])),
        },
        "deep_plain_english_assessment": {
            "architecture_analysis": (
                "KT looks most novel as a constitutional governance and authority stack. The architecture clearly improves claim discipline and replayable authority tracking. "
                "It does not yet prove broad runtime superiority or broad scale readiness."
            ),
            "governance_spine": (
                "This is KT's strongest layer. Governance is not just decorative docs; it actively constrains live posture through receipts, predicates, and supersession rules."
            ),
            "trust_model": (
                "Trust is stronger internally than externally. Prompt hashes, authority partition, secret-exclusion rules, and clean lineage are real, "
                "but same-host and branch-local limits still constrain outside trust."
            ),
            "runtime_system": (
                "The runtime is real in the narrow local verifier wedge. It is not yet broadly hardened or externally ratified beyond that wedge."
            ),
            "validator_and_testing": (
                "Validators and focused tranche tests meaningfully improve reliability, especially around stale-surface and claim-drift prevention. "
                "They are strongest on structural and authority correctness, weaker as proof of broad runtime semantic correctness."
            ),
            "formal_methods_and_supply_chain": (
                "KT behaves like a system that values invariants and provenance, but Track 02 does not prove deep formal verification or full enterprise supply-chain completeness."
            ),
            "external_verifiability": (
                "Outsiders can inspect a lot, but third-party rerun and external ratification are still limited. This is not yet independent public verification at frontier-lab level."
            ),
            "capability_vs_claims": (
                "KT's discipline here is unusually strong. It claims less than most ambitious AI repos, and Track 02 confirms that the real strength is governance plus one bounded proof, not broad capability dominance."
            ),
            "adversarial_robustness": (
                "KT is strongest against narrative inflation, stale-authority confusion, and claim-boundary collapse. It is weaker against criticism that the runtime surface is still too narrow and commercially unproven."
            ),
            "complexity_analysis": (
                "Complexity is a real cost. The system works because discipline is high; if discipline slips, artifact volume and layered courts could become a fragility source."
            ),
            "commercialization_analysis": (
                "Commercial standing remains weak. The honest product today is one bounded verifier-backed wedge with no customer, revenue, enterprise, or multi-tenant proof."
            ),
            "novelty_analysis": (
                "Novelty appears strongest in the governance, authority, and receipt architecture. Broad AI-model or runtime novelty is not yet established by this audit."
            ),
        },
        "explicit_final_answers": explicit_answers,
        "what_kt_can_safely_claim_now": [
            "Gate D cleared on the successor line.",
            "Gate E open on the successor line.",
            "Gate F confirmed as one narrow local_verifier_mode wedge only.",
            "Post-F broad canonical re-audit passed.",
            "Track 01 provides repeated bounded category-fair advantage on the confirmed wedge.",
            "Track 02 preserves separate baseline and current-truth verdicts with a clean delta crosswalk.",
        ],
        "what_kt_still_cannot_safely_claim": [
            "Best AI.",
            "Broad model superiority.",
            "Full-system superiority.",
            "Router or lobe superiority.",
            "Enterprise readiness.",
            "Multi-tenant legitimacy.",
            "Broad commercial validation.",
            "Cross-host runtime superiority.",
            "Public benchmark or Kaggle carryover.",
        ],
        "top_open_blockers": unresolved_blockers,
        "benchmark_readiness_map": benchmark_readiness,
        "prompt_gap_honesty_note": (
            "Track 02 gets closer to the severe adversarial review standard, but it still does not emit a full 15-axis 0-100 frontier teardown. "
            "It is best read as a strong constitutional adversarial audit of the live bounded system, not yet the final full-spectrum frontier dossier."
        ),
        "source_refs": common.output_ref_dict(
            scope_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}"),
            execution_receipt=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{audit_tranche.OUTPUT_RECEIPT}"),
            baseline_audit_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_packet.json"),
            current_truth_audit_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_packet.json"),
            delta_crosswalk=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_delta_crosswalk.json"),
            meta_summary=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_meta_summary.json"),
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_final_summary_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "separate_verdicts_preserved": True,
        "english_executive_brief_bound": True,
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Track 02 Final Summary Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Summary outcome: `{SUMMARY_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Frozen baseline verdict: `{meta_summary.get('baseline_audit_reference', {}).get('top_level_verdict', '')}`",
            f"- Current-truth verdict: `{current_packet.get('top_level_verdict', '')}`",
            f"- Single-sentence read: `{final_verdict.get('single_sentence_verdict', '')}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    scope_packet_path: Path,
    execution_receipt_path: Path,
    baseline_packet_path: Path,
    baseline_receipt_path: Path,
    current_packet_path: Path,
    current_receipt_path: Path,
    delta_crosswalk_path: Path,
    delta_receipt_path: Path,
    meta_summary_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != scope_tranche.REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 02 final summary must run on {scope_tranche.REQUIRED_WORKING_BRANCH}, got {branch_name}")

    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 02 final summary requires a clean worktree before execution")

    scope_packet = common.load_json_required(root, scope_packet_path, label="Track 02 scope packet")
    execution_receipt = common.load_json_required(root, execution_receipt_path, label="Track 02 dual-audit execution receipt")
    baseline_packet = common.load_json_required(root, baseline_packet_path, label="Track 02 frozen baseline audit packet")
    baseline_receipt = common.load_json_required(root, baseline_receipt_path, label="Track 02 frozen baseline audit receipt")
    current_packet = common.load_json_required(root, current_packet_path, label="Track 02 current-truth audit packet")
    current_receipt = common.load_json_required(root, current_receipt_path, label="Track 02 current-truth audit receipt")
    delta_crosswalk = common.load_json_required(root, delta_crosswalk_path, label="Track 02 delta crosswalk")
    delta_receipt = common.load_json_required(root, delta_receipt_path, label="Track 02 delta crosswalk receipt")
    meta_summary = common.load_json_required(root, meta_summary_path, label="Track 02 meta summary")

    _require_pass(scope_packet, label="Track 02 scope packet")
    _require_pass(execution_receipt, label="Track 02 dual-audit execution receipt")
    _require_pass(baseline_packet, label="Track 02 frozen baseline audit packet")
    _require_pass(baseline_receipt, label="Track 02 frozen baseline audit receipt")
    _require_pass(current_packet, label="Track 02 current-truth audit packet")
    _require_pass(current_receipt, label="Track 02 current-truth audit receipt")
    _require_pass(delta_crosswalk, label="Track 02 delta crosswalk")
    _require_pass(delta_receipt, label="Track 02 delta crosswalk receipt")
    _require_pass(meta_summary, label="Track 02 meta summary")

    if str(execution_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_02_FINAL_SUMMARY_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 02 execution receipt does not authorize the final summary packet")
    if not bool(meta_summary.get("forbidden_behaviors_compliance", {}).get("baseline_and_current_truth_verdicts_not_blended", False)):
        raise RuntimeError("FAIL_CLOSED: Track 02 final summary requires preserved separate verdicts")

    subject_head = str(scope_packet.get("subject_head", "")).strip() or str(execution_receipt.get("current_truth_anchor_commit", "")).strip()
    outputs = build_outputs(
        root=root,
        subject_head=subject_head,
        branch_name=branch_name,
        scope_packet=scope_packet,
        execution_receipt=execution_receipt,
        baseline_packet=baseline_packet,
        baseline_receipt=baseline_receipt,
        current_packet=current_packet,
        current_receipt=current_receipt,
        delta_crosswalk=delta_crosswalk,
        delta_receipt=delta_receipt,
        meta_summary=meta_summary,
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
        "summary_outcome": SUMMARY_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the Track 02 final summary packet.")
    parser.add_argument(
        "--scope-packet",
        default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--execution-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{audit_tranche.OUTPUT_RECEIPT}",
    )
    parser.add_argument(
        "--baseline-packet",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
    )
    parser.add_argument(
        "--baseline-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
    )
    parser.add_argument(
        "--current-packet",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_packet.json",
    )
    parser.add_argument(
        "--current-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_receipt.json",
    )
    parser.add_argument(
        "--delta-crosswalk",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_delta_crosswalk.json",
    )
    parser.add_argument(
        "--delta-receipt",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.json",
    )
    parser.add_argument(
        "--meta-summary",
        default=f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_meta_summary.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        execution_receipt_path=common.resolve_path(root, args.execution_receipt),
        baseline_packet_path=common.resolve_path(root, args.baseline_packet),
        baseline_receipt_path=common.resolve_path(root, args.baseline_receipt),
        current_packet_path=common.resolve_path(root, args.current_packet),
        current_receipt_path=common.resolve_path(root, args.current_receipt),
        delta_crosswalk_path=common.resolve_path(root, args.delta_crosswalk),
        delta_receipt_path=common.resolve_path(root, args.delta_receipt),
        meta_summary_path=common.resolve_path(root, args.meta_summary),
    )
    print(result["summary_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
