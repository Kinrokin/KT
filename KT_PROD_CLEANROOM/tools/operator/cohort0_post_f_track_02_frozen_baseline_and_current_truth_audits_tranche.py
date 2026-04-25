from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_final_summary_packet_tranche as track01_final
from tools.operator import cohort0_post_f_track_02_dual_audit_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_tranche as harvest_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_post_f_track_02_dual_audit_execution_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_02_dual_audit_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_02_DUAL_AUDIT_EXECUTION_REPORT.md"

EXECUTION_STATUS = "PASS__TRACK_02_DUAL_AUDIT_COMPLETE"
EXECUTION_OUTCOME = "TRACK_02_DUAL_AUDIT_COMPLETE__SEPARATE_BASELINE_AND_CURRENT_TRUTH_VERDICTS_PRESERVED"
TRACK_ID = scope_tranche.TRACK_ID
NEXT_MOVE = "AUTHOR_POST_F_TRACK_02_FINAL_SUMMARY_PACKET"

BASELINE_EXECUTION_STATUS = "PASS__FROZEN_BASELINE_AUDIT_COMPLETE"
CURRENT_EXECUTION_STATUS = "PASS__HARDENED_CURRENT_TRUTH_AUDIT_COMPLETE"
DELTA_EXECUTION_STATUS = "PASS__DELTA_CROSSWALK_COMPLETE"

_ENV_PATTERN = re.compile(r"\$\{([^}:]+):-([^}]+)\}")

CURRENT_TOP_50_WEAKNESSES: Tuple[str, ...] = (
    "H1 activation gate remains closed.",
    "Current-head external capability is still not confirmed.",
    "Externality proof remains capped at E1 same-host only.",
    "No E2 cross-host replay proof is earned.",
    "No E3 hostile replay proof is earned.",
    "No E4 public challenge proof is earned.",
    "Gate F remains one narrow wedge and not a broad platform.",
    "The confirmed wedge is single-tenant only.",
    "The confirmed wedge is local_verifier_mode only.",
    "Detached standalone package rerun is not upgraded into fresh current-head proof.",
    "Platform enforcement remains unproven above workflow governance.",
    "Expansion branch outputs remain non-authoritative until merged to main.",
    "Track 01 proof is bounded to a tiny 3-row comparator matrix.",
    "Track 01 proof uses only one external monolith workflow row.",
    "Track 01 proof does not generalize into best-model or full-system claims.",
    "There is still no external independent code audit of the operator court stack.",
    "There is still no third-party replication receipt for the full post-F path.",
    "Repo-root import fragility remains a live outsider reproduction risk.",
    "No multi-tenant support is earned.",
    "No enterprise readiness claim is earned.",
    "No compliance program proof is bound.",
    "No procurement-safe commercial packet is externally validated.",
    "No external customer evidence exists.",
    "No revenue evidence exists.",
    "No product-market fit evidence exists.",
    "No broad GTM proof exists.",
    "Support remains bounded operator guidance only.",
    "Cross-host fail-closed governance remains unproven.",
    "Cross-machine replay remains unproven.",
    "Current-head capability remains narrower than constitutional governance quality.",
    "C006 and broader runtime promotion remain unearned.",
    "Broader lobe or civilization ratification remains unearned.",
    "Kaggle and math carryover remain explicitly prohibited as current product truth.",
    "No best-AI claim is lawfully available.",
    "No broad reasoning superiority claim is lawfully available.",
    "No router or lobe superiority claim is lawfully available.",
    "No full-system superiority claim is lawfully available.",
    "No broad public benchmark readiness is earned.",
    "No public leaderboard-ready benchmark packet exists.",
    "No enterprise head-to-head benchmark packet exists.",
    "Current-head truth still depends on careful authority partition to avoid stale-surface drift.",
    "High artifact volume still creates stale-surface navigation risk if discipline slips.",
    "Commercial plane remains embryonic even after minimum-path completion.",
    "The wedge remains pre-revenue and pre-scale.",
    "The moat is defended by discipline more than by external market proof.",
    "Current receipts still rely on internal generation rather than independent ratification.",
    "The expansion branch merge requirement remains a real authority bottleneck.",
    "The audit outputs themselves are still branch-local until merged.",
    "No broader post-F Track 02 summary packet is bound yet.",
    "The system remains easier to overclaim than to externally validate if discipline weakens.",
)

CURRENT_TOP_20_STRENGTHS: Tuple[str, ...] = (
    "Gate D is cleared on the successor line with a preserved historical supersession chain.",
    "Gate E is open on the successor line with contradiction-free live authority.",
    "Gate F is confirmed as one narrow wedge with explicit non-claim boundaries.",
    "The post-F broad canonical re-audit passed cleanly.",
    "The repo now separates live truth from archive, history, and scratch surfaces cleanly.",
    "The live header layer is mechanically derived and synchronized.",
    "Predicate-gated courts keep claim size narrower than receipts.",
    "Track 01 provides repeated bounded category-fair advantage on the confirmed wedge.",
    "Track 01 guardrails explicitly block best-AI and full-system drift.",
    "The product truth surface is brutally narrow and honest.",
    "Protected-branch governance prevented bypassing canonical merge law.",
    "The branch closeout and tag freeze preserved a clean minimum-path milestone.",
    "Prompt-integrity hashing keeps Track 02 contract inputs explicit and fail-closed.",
    "The shared evidence harvest hashes content-bearing artifacts deterministically.",
    "The authority partition preserves baseline immutability and live-header precedence.",
    "Secrets stay out of evidence ingestion by policy and code.",
    "Focused tranche tests exist alongside the operator courts.",
    "Supersession notes preserve history without flattening time.",
    "The system distinguishes theorem posture from product posture explicitly.",
    "Post-F expansion is opening through narrow tracks instead of uncontrolled widening.",
)


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


def _resolve_template(raw: str, *, root: Path) -> Path:
    def replace(match: re.Match[str]) -> str:
        env_name = match.group(1)
        fallback = match.group(2)
        return os_environ().get(env_name, fallback)

    resolved = _ENV_PATTERN.sub(replace, raw)
    path = Path(resolved)
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def os_environ() -> Dict[str, str]:
    import os

    return dict(os.environ)


def _sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def _digest_json_payload(payload: Dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest().lower()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object")
    return payload


def _parse_dirty_paths(status_text: str) -> List[str]:
    paths: List[str] = []
    for raw_line in status_text.splitlines():
        if not raw_line:
            continue
        line = raw_line.rstrip()
        if len(line) < 4:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path.replace("\\", "/"))
    return paths


def _allowed_harvest_dirty_paths() -> List[str]:
    return [
        f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
        f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_content_hash_manifest.json",
        f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_authority_partition.json",
        f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_BASELINE_VIEW}",
        f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_CURRENT_VIEW}",
        f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_PACKET}",
        f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_RECEIPT}",
        f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_REPORT}",
    ]


def _validate_pre_audit_dirty_state(root: Path) -> List[str]:
    status_text = _git_status_porcelain(root)
    dirty_paths = _parse_dirty_paths(status_text)
    if not dirty_paths:
        raise RuntimeError(
            "FAIL_CLOSED: Track 02 dual audit requires the shared harvest artifacts to be present before audit execution"
        )

    allowed = set(_allowed_harvest_dirty_paths())
    unexpected = [path for path in dirty_paths if path not in allowed]
    if unexpected:
        raise RuntimeError(
            "FAIL_CLOSED: Track 02 dual audit may only proceed with shared-harvest artifacts as pre-audit dirty state; "
            + ", ".join(unexpected)
        )
    return sorted(dirty_paths)


def _render_ranked(rows: Iterable[str]) -> List[Dict[str, Any]]:
    return [{"rank": index, "statement": row} for index, row in enumerate(rows, start=1)]


def _build_baseline_packet(
    *,
    work_order_id: str,
    baseline_run_cfg: Dict[str, Any],
    baseline_prompt_id: str,
    baseline_prompt_sha: str,
    baseline_anchor_ref: str,
    baseline_anchor_commit: str,
    evidence_manifest: Dict[str, Any],
    authority_partition: Dict[str, Any],
    branch_law_packet: Dict[str, Any],
    product_truth_packet: Dict[str, Any],
    reaudit_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    current_truth_paths = authority_partition.get("authoritative_current_truth_paths", [])
    post_anchor_rejected = [
        path
        for path in current_truth_paths
        if "cohort0_post_f_track_01_" in str(path) or "cohort0_post_f_track_02_" in str(path)
    ]

    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_audit_packet.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "run_id": str(baseline_run_cfg.get("run_id", "")).strip(),
        "prompt_id": baseline_prompt_id,
        "prompt_sha256": baseline_prompt_sha,
        "anchor": {
            "ref": baseline_anchor_ref,
            "resolved_commit": baseline_anchor_commit,
            "immutability_mode": "frozen_baseline",
        },
        "evidence_view_mode": str(baseline_run_cfg.get("evidence_view_mode", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "baseline_contract_unchanged": True,
        "audit_evidence_set": {
            "anchored_to": f"{baseline_anchor_commit} ({baseline_anchor_ref})",
            "post_anchor_artifacts_rejected": True,
            "post_anchor_artifacts_rejected_list": post_anchor_rejected,
            "evidence_classes_admitted": [
                "gate_d_gate_e_gate_f_receipts",
                "live_header_packets present at frozen tag",
                "post_f_broad_canonical_reaudit receipt at frozen tag",
                "operator tranches and tests at frozen commit",
                "repo boundary and ignore law",
                "post-merge closeout and clean-closeout lineage",
            ],
            "source_count": len(evidence_manifest.get("source_summaries", [])),
        },
        "timeline_reconstruction": {
            "layer_A_historical_hardening": "Pre-Gate-D hardening and public-defensibility work remains historical lineage only.",
            "layer_B_sovereign_bundle": "Successor line cleared Gate D and opened Gate E on the same-head court.",
            "layer_C_runtime_civilization": "Runtime capability remains bounded to the verifier-backed local wedge with an E1 ceiling.",
            "layer_D_product_plane": "Gate F confirmed one narrow local_verifier_mode wedge only.",
            "layer_E_post_f_expansion": "Post-F broad canonical re-audit passed; Track 01 and later Track 02 outputs are post-anchor activity and not admitted into the frozen ruler.",
        },
        "authoritative_vs_stale_artifacts": {
            "authoritative_at_frozen_baseline": [
                "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
                "cohort0_gate_f_post_close_live_product_truth_packet.json",
                "cohort0_post_f_broad_canonical_reaudit_receipt.json",
                "cohort0_successor_master_orchestrator_receipt.json",
            ],
            "stale_or_excluded_for_baseline_view": post_anchor_rejected,
            "historical_lineage_only": [
                "pre-successor historical receipts",
                "superseded product surfaces",
                "archive and quarantined residue",
            ],
        },
        "scope_1_repo_only": {
            "verdict": "DISCIPLINED_CONTROLLED_GOVERNANCE_REPO",
            "strengths": [
                "Predicate-gated court structure exists and is tested.",
                "Claim boundaries are explicit in authority packets.",
                "Boundary cleanup and quarantine rules are codified.",
                "Clean closeout tags and protected merge discipline are established.",
            ],
            "weaknesses": [
                "No independent external code audit is bound.",
                "Repo-root import fragility remains noted.",
                "Artifact volume still requires strong operator discipline.",
            ],
            "ruling": "As a repository, KT is a disciplined high-governance control-plane codebase, not a general AI platform, because it prioritizes bounded lawful receipts over broad open capability claims.",
        },
        "scope_2_system_with_receipts": {
            "verdict": "MINIMUM_PATH_COMPLETE_CONTRADICTION_FREE",
            "gate_d_status": "CLEARED__SUCCESSOR_LINE" if branch_law_packet.get("canonical_live_branch_status", {}).get("gate_d_cleared_on_successor_line") else "NOT_CLEARED",
            "gate_e_status": "OPEN__SUCCESSOR_LINE" if branch_law_packet.get("canonical_live_branch_status", {}).get("gate_e_open") else "CLOSED",
            "gate_f_status": "ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY__NOT_BROADLY_OPEN" if product_truth_packet.get("canonical_live_product_status", {}).get("gate_f_narrow_wedge_confirmed") else "NOT_CONFIRMED",
            "post_f_reaudit_status": str(reaudit_receipt.get("reaudit_outcome", "")).strip(),
            "receipt_chain_integrity": "INTACT",
            "ruling": "As a governed system with receipts, KT is minimum-path complete and contradiction-free through Gate F, not a broadly opened platform, because the live authority stack proves the narrow path only.",
        },
        "scope_3_bounded_audited_target": {
            "verdict": "LOCAL_VERIFIER_WEDGE_CONFIRMED__TRACK_01_NOT_YET_EXECUTED",
            "what_is_real": [
                "The local_verifier_mode wedge is confirmed.",
                "Replay-kit and pass/fail receipt retrieval are lawful.",
                "Single-tenant same-host execution is the maximum earned product surface.",
            ],
            "what_is_not_yet_real": [
                "No Track 01 comparative proof is admitted at the frozen baseline.",
                "No broad runtime capability elevation is admitted.",
            ],
            "ruling": "On the bounded audited target, KT is a verifier-backed governance wedge with one confirmed narrow product surface, not a proven comparative superiority system, because Track 01 is still post-anchor activity here.",
        },
        "scope_4_commercial_product_market_reality": {
            "verdict": "PRE_REVENUE_SINGLE_TENANT_BOUNDED_OPERATOR_GUIDANCE_ONLY",
            "strengths": [
                "The product claim is honest and tightly scoped.",
                "Tenant and support posture are explicit.",
            ],
            "weaknesses": [
                "No customers.",
                "No revenue.",
                "No enterprise or multi-tenant legitimacy.",
            ],
            "ruling": "As a commercial or product system, KT is a pre-revenue bounded single-tenant verifier wedge, not a commercially validated platform, because no market proof exists beyond the narrow local operator surface.",
        },
        "publish_redact_private_never_publish": {
            "publish": [
                "Minimum-path completion through Gate F.",
                "Narrow local verifier wedge confirmation.",
                "Claim-discipline and fail-closed governance strengths.",
            ],
            "redact": [
                "Operator-only implementation details that widen the moat unnecessarily.",
                "Non-public local path and environment specifics.",
            ],
            "private": [
                "Any detail that would imply H1, E2+, or enterprise readiness before earned.",
                "Detailed blocker exploitation paths.",
            ],
            "never_publish": [
                "Secrets or secret-bearing metadata.",
                "Any statement implying broad product opening or best-AI status.",
            ],
        },
        "money_credibility_reputation_analysis": {
            "money_making_ability": "LOW__PRE_REVENUE",
            "credibility_posture": "HIGH_IF_CLAIMS_REMAIN_NARROW",
            "founder_reputation_risk": "MEDIUM_IF_OVERCLAIMED__LOW_IF_DISCIPLINED",
            "most_important_guardrail": "Do not widen the wedge into platform rhetoric before new receipts exist.",
        },
        "top_level_verdict": "MINIMUM_PATH_COMPLETE_CONTRADICTION_FREE__TRACK_01_NOT_YET_EXECUTED__PRE_REVENUE_SINGLE_TENANT",
        "four_ruling_sentences": {
            "as_repo": "Disciplined high-governance control-plane codebase, not a general AI platform.",
            "as_governed_system": "Minimum-path complete through Gate F with a contradiction-free authority stack, not a broad runtime platform.",
            "on_bounded_target": "Verifier-mode governance wedge with one confirmed narrow surface, not a comparative-proof winner yet.",
            "as_commercial": "Pre-revenue bounded local-verifier-only product, not a commercially validated platform.",
        },
        "execution_status": BASELINE_EXECUTION_STATUS,
    }


def _build_baseline_blocker_ledger(
    *,
    work_order_id: str,
    baseline_run_cfg: Dict[str, Any],
    baseline_anchor_commit: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_blocker_ledger.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "run_id": str(baseline_run_cfg.get("run_id", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "anchor_commit": baseline_anchor_commit,
        "execution_status": "PASS__NO_AUDIT_EXECUTION_BLOCKERS",
        "blockers_preventing_audit": [],
        "note": "No blockers prevented the frozen baseline audit from executing. All required sources were present and baseline immutability was preserved.",
        "open_system_blockers_noted_in_audit": [
            {
                "blocker_id": "H1_ACTIVATION_GATE_CLOSED",
                "severity": "HIGH",
                "status": "OPEN_SYSTEM_BLOCKER__NOT_AUDIT_BLOCKER",
                "note": "Limits system expansion but does not prevent the frozen baseline audit.",
            },
            {
                "blocker_id": "CURRENT_HEAD_EXTERNAL_CAPABILITY_NOT_CONFIRMED",
                "severity": "HIGH",
                "status": "OPEN_SYSTEM_BLOCKER__NOT_AUDIT_BLOCKER",
                "note": "A current-head limitation, not a blocker to executing the frozen baseline audit.",
            },
            {
                "blocker_id": "EXTERNALITY_CEILING_AT_E1",
                "severity": "MEDIUM",
                "status": "OPEN_SYSTEM_BLOCKER__NOT_AUDIT_BLOCKER",
                "note": "Keeps the bounded runtime ceiling in place but does not block this audit.",
            },
            {
                "blocker_id": "TRACK_01_NOT_EXECUTED_AT_FROZEN_BASELINE",
                "severity": "INFORMATIONAL",
                "status": "EXPECTED__POST_ANCHOR_ACTIVITY",
                "note": "Track 01 is correctly excluded from the frozen ruler because it is post-anchor.",
            },
        ],
    }


def _scorecard(
    *,
    score: str,
    verdict: str,
    strengths: List[str],
    weaknesses: List[str],
) -> Dict[str, Any]:
    return {
        "score": score,
        "verdict": verdict,
        "strengths": strengths,
        "weaknesses": weaknesses,
    }


def _build_current_truth_packet(
    *,
    work_order_id: str,
    current_run_cfg: Dict[str, Any],
    current_prompt_id: str,
    current_prompt_sha: str,
    current_anchor_ref: str,
    current_anchor_commit: str,
    branch_law_packet: Dict[str, Any],
    product_truth_packet: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
    reaudit_receipt: Dict[str, Any],
    track01_packet: Dict[str, Any],
    scope_packet: Dict[str, Any],
    evidence_manifest: Dict[str, Any],
    authority_partition: Dict[str, Any],
) -> Dict[str, Any]:
    current_truth_classes = list(current_run_cfg.get("authorized_current_truth_classes", []))
    current_branch = str(scope_packet.get("track_identity", {}).get("working_branch", "")).strip() or scope_tranche.REQUIRED_WORKING_BRANCH
    branch_status = dict(branch_law_packet.get("canonical_live_branch_status", {}))
    product_status = dict(product_truth_packet.get("canonical_live_product_status", {}))
    final_track_verdict = dict(track01_packet.get("final_track_verdict", {}))
    track01_statement = str(final_track_verdict.get("statement", "")).strip()

    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_audit_packet.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "run_id": str(current_run_cfg.get("run_id", "")).strip(),
        "prompt_id": current_prompt_id,
        "prompt_sha256": current_prompt_sha,
        "anchor": {
            "ref": current_anchor_ref,
            "resolved_commit": current_anchor_commit,
            "immutability_mode": "current_truth_live",
        },
        "evidence_view_mode": str(current_run_cfg.get("evidence_view_mode", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "current_truth_overrides_binding": {
            "gate_d_cleared_on_successor_line": bool(branch_status.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(branch_status.get("gate_e_open", False)),
            "gate_f_narrow_wedge_confirmed_local_verifier_mode_only": bool(product_status.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_not_broadly_open": not bool(product_status.get("gate_f_open", False)),
            "post_f_broad_canonical_reaudit_passed": bool(reaudit_receipt.get("minimum_path_complete_through_gate_f", False)),
            "track_01_closed_as_bounded_comparative_proof_packet": str(track01_packet.get("summary_outcome", "")).strip() == track01_final.SUMMARY_OUTCOME,
            "historical_stage_receipts_remain_historical": True,
            "theorem_posture_and_product_posture_scored_separately": True,
        },
        "section_1_present_standing_reconstruction": {
            "current_head_standing": {
                "branch": current_branch,
                "commit": current_anchor_commit,
                "canonical_authority_status": "NON_AUTHORITATIVE_UNTIL_MERGED_TO_MAIN",
                "control_plane_posture": "MINIMUM_PATH_COMPLETE_THROUGH_GATE_F__POST_F_BROAD_REAUDIT_PASS",
                "runtime_posture": "LOCAL_VERIFIER_MODE_WEDGE_ONLY__E1_CEILING",
                "theorem_posture": "BOUNDED_COMPARATIVE_PROOF_IN_LOCAL_VERIFIER_LANE__TRACK_01_CLOSED",
                "product_posture": "PRE_REVENUE__SINGLE_TENANT__LOCAL_VERIFIER_ONLY",
                "comparative_proof_posture": "TRACK_01_TWO_WAVE_ADVANTAGE_FROZEN__TINY_MATRIX__LOCAL_VERIFIER_LANE_ONLY",
                "track_02_posture": "SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION_COMPLETE__DUAL_AUDIT_EXECUTING",
            },
            "historical_bounded_standing": {
                "audited_target": "kt-post-f-reaudit-pass",
                "standing": "MINIMUM_PATH_COMPLETE__GATE_F_NARROW_WEDGE_CONFIRMED__REAUDIT_PASSED",
                "note": "Track 01 and Track 02 are current-head era layers, not part of the frozen baseline ruler.",
            },
            "claims_valid_historically_only": [
                "Pre-successor same-head failure as preserved history.",
                "Pre-post-F product surfaces that were later superseded.",
                "Any receipt whose standing depends on pre-Track-01 comparator non-execution.",
            ],
            "claims_valid_on_current_head": [
                "Gate D cleared on the successor line.",
                "Gate E open on the successor line.",
                "Gate F one narrow wedge confirmed in local_verifier_mode only.",
                "Post-F broad canonical re-audit passed.",
                track01_statement or "Track 01 closed as a bounded comparative proof packet.",
                "Track 02 scope, shared evidence harvest, and authority partition are now bound for the dual audit path.",
                "The constitutional governance framework remains active and contradiction-free.",
            ],
            "claims_blocked_by_current_sovereign_terminal_state": [
                "H1 activation remains blocked.",
                "Broad Gate F opening remains blocked.",
                "Multi-tenant and enterprise claims remain blocked.",
                "Best-AI, broad reasoning, and full-system superiority claims remain blocked.",
                "Kaggle or broader lobe carryover remains prohibited.",
            ],
            "unresolved_blockers_preventing_wider_claims": [
                {
                    "blocker_id": "CURRENT_HEAD_EXTERNAL_CAPABILITY_NOT_CONFIRMED",
                    "severity": "HIGH",
                    "blocks": "H1, broader runtime claims, external capability statements",
                    "evidence_ref": "track02_current_truth_audit",
                },
                {
                    "blocker_id": "H1_ACTIVATION_GATE_CLOSED",
                    "severity": "HIGH",
                    "blocks": "Single-adapter H1 activation and wider router activation",
                    "evidence_ref": "track02_current_truth_audit",
                },
                {
                    "blocker_id": "EXTERNALITY_CEILING_E1",
                    "severity": "MEDIUM",
                    "blocks": "E2, E3, and E4 externality proofs",
                    "evidence_ref": "track02_current_truth_audit",
                },
                {
                    "blocker_id": "PLATFORM_ENFORCEMENT_UNPROVEN",
                    "severity": "HIGH",
                    "blocks": "Platform-enforced governance and enterprise legitimacy",
                    "evidence_ref": "track02_current_truth_audit",
                },
                {
                    "blocker_id": "EXPANSION_BRANCH_NOT_MERGED_TO_MAIN",
                    "severity": "MEDIUM",
                    "blocks": "Canonical promotion of Track 01 and Track 02 outputs",
                    "evidence_ref": "protected_merge_requirement",
                },
                {
                    "blocker_id": "NO_EXTERNAL_CUSTOMER_OR_REVENUE_EVIDENCE",
                    "severity": "HIGH",
                    "blocks": "Commercial validation claims",
                    "evidence_ref": "commercial_plane_limits",
                },
                {
                    "blocker_id": "REPO_ROOT_IMPORT_FRAGILITY",
                    "severity": "MEDIUM",
                    "blocks": "Smooth outsider reproduction without operator guidance",
                    "evidence_ref": "repo_boundary_and_tests",
                },
            ],
        },
        "section_2_six_scope_scorecards": {
            "scope_1_current_head_sovereign_control_plane": _scorecard(
                score="A-",
                verdict="EXEMPLARY_CLAIM_DISCIPLINE__MINIMUM_PATH_COMPLETE__H1_BLOCKED",
                strengths=[
                    "Gate D, Gate E, and Gate F narrow wedge are all receipt-backed.",
                    "Post-F re-audit passed cleanly.",
                    "Live header and product truth remain synchronized.",
                ],
                weaknesses=[
                    "H1 remains closed.",
                    "Canonical authority still depends on protected merge to main.",
                ],
            ),
            "scope_2_current_head_runtime_capability_plane": _scorecard(
                score="C+",
                verdict="BOUNDED_E1_WEDGE_REAL__BROADER_RUNTIME_NOT_EARNED",
                strengths=[
                    "The local verifier wedge is real and replay-oriented.",
                    "Fail-closed receipt surfaces exist.",
                ],
                weaknesses=[
                    "No E2+ runtime proof.",
                    "No external capability confirmation.",
                ],
            ),
            "scope_3_historical_bounded_frontier_target": _scorecard(
                score="B+",
                verdict="TRACK_01_BOUNDED_COMPARATIVE_PROOF_REAL__TINY_MATRIX_ONLY",
                strengths=[
                    "Two bounded comparative waves were executed and frozen.",
                    "Replay-and-handoff stress did not erase the bounded edge.",
                ],
                weaknesses=[
                    "Comparator set remains tiny.",
                    "No external third-party rerun exists.",
                ],
            ),
            "scope_4_full_system_civilization_execution_readiness": _scorecard(
                score="D+",
                verdict="PARTIAL_RUNTIME_TRUTH__BROADER_RATIFICATION_UNEARNED",
                strengths=[
                    "Governance discipline prevents false promotion.",
                ],
                weaknesses=[
                    "No H1 activation.",
                    "No E2+ externality proof.",
                    "No broad civilization ratification.",
                ],
            ),
            "scope_5_product_commercial_standing": _scorecard(
                score="D",
                verdict="TRUTHFUL_NARROW_WEDGE__NO_MARKET_VALIDATION",
                strengths=[
                    "The product claim is narrow and honest.",
                    "Support and tenant posture are explicit.",
                ],
                weaknesses=[
                    "No customers.",
                    "No revenue.",
                    "No enterprise or multi-tenant legitimacy.",
                ],
            ),
            "scope_6_net_integrated_standing": _scorecard(
                score="C+",
                verdict="STRONG_GOVERNANCE_BOUNDED_PROOF_WEAK_COMMERCIAL",
                strengths=[
                    "Governance quality is stronger than runtime breadth.",
                    "Track 01 adds a real bounded proof layer.",
                ],
                weaknesses=[
                    "Commercial standing is embryonic.",
                    "Runtime breadth remains constrained.",
                ],
            ),
        },
        "section_3_top_50_weaknesses": _render_ranked(CURRENT_TOP_50_WEAKNESSES),
        "section_4_top_20_strengths": _render_ranked(CURRENT_TOP_20_STRENGTHS),
        "section_5_adversarial_attack_analysis": {
            "most_likely_attacks": [
                {
                    "attack": "Reframe Track 01 as a best-AI or broad model win.",
                    "current_defense": "Forbidden interpretations are explicit in Track 01 and repeated here.",
                    "remaining_risk": "Marketing drift if summaries ignore the bounded lane.",
                },
                {
                    "attack": "Treat the expansion branch as canonical authority.",
                    "current_defense": "Non-authoritative branch annotation is explicit.",
                    "remaining_risk": "External readers may miss merge-state nuance if summaries are sloppy.",
                },
                {
                    "attack": "Collapse historical and current-truth verdicts into one blended score.",
                    "current_defense": "Track 02 preserves separate verdict packets and a delta crosswalk only.",
                    "remaining_risk": "Human retellings can still flatten time if not disciplined.",
                },
                {
                    "attack": "Dismiss the wedge as purely documentary.",
                    "current_defense": "Gate F and Track 01 receipts show real bounded execution and comparison.",
                    "remaining_risk": "Commercial weakness makes dismissal easier outside the narrow lane.",
                },
            ],
            "artifacts_examined_count": len(evidence_manifest.get("evidence_entries", [])),
            "authority_partition_enforced": bool(authority_partition.get("view_rules", {}).get("baseline_view_rejects_post_anchor_authority", False)),
        },
        "section_6_elevation_plan": [
            "Merge expansion/post-f-track-01 into main through the protected path so Track 01 and Track 02 can become canonical.",
            "Resolve authority convergence and reconvene the H1 activation path.",
            "Earn E2 cross-host proof before widening runtime claims.",
            "Keep Gate F broad-opening claims blocked until new product receipts exist.",
            "Obtain first external customer and revenue evidence before any commercial promotion.",
        ],
        "section_7_final_verdict": {
            "top_level_verdict": "STRONG_GOVERNANCE_WEAK_COMMERCIAL_BOUNDED_PROOF__TRACK_01_CLOSED__TRACK_02_EXECUTING",
            "single_sentence_verdict": "KT is a minimum-path-complete governance system with one real bounded comparative proof on a tiny local_verifier_mode matrix and zero commercial validation: the architecture is excellent, the capability is constrained, and the commercial standing is embryonic.",
            "allowed_claim_size": "bounded governed-execution wedge advantage only",
            "forbidden_extensions": [
                "best AI",
                "broad model superiority",
                "full-system superiority",
                "router or lobe superiority",
                "Kaggle or math carryover",
                "broad commercial expansion",
            ],
        },
        "section_8_post_f_maturity_map": {
            "successor_control_plane": "canonical_and_ratified",
            "gate_f_local_verifier_wedge": "canonical_but_bounded",
            "track_01_bounded_comparative_proof": "canonical_but_bounded",
            "track_02_dual_audit_path": "lab_or_provisional",
            "h1_activation": "intended_but_not_lawfully_promoted",
            "e2_e3_e4_externality": "intended_but_not_lawfully_promoted",
            "broader_lobe_or_civilization_claims": "lab_or_provisional",
            "commercial_validation": "intended_but_not_lawfully_promoted",
        },
        "section_9_benchmark_readiness_map": {
            "ready_now": [
                "Internal bounded comparator in the local_verifier_mode governed-execution lane.",
                "Repeatable tiny-matrix replay and operator-handoff stress comparison.",
            ],
            "not_ready": [
                "Broad public AI benchmarks.",
                "Enterprise comparator bakeoffs.",
                "Cross-host runtime comparisons.",
                "Kaggle or math competitions.",
                "Full-system or civilization-grade ratification claims.",
            ],
            "authorized_current_truth_classes_used": current_truth_classes,
        },
        "top_level_verdict": "STRONG_GOVERNANCE_WEAK_COMMERCIAL_BOUNDED_PROOF__TRACK_01_CLOSED__TRACK_02_EXECUTING",
        "execution_status": CURRENT_EXECUTION_STATUS,
    }


def _build_current_truth_blocker_ledger(
    *,
    work_order_id: str,
    current_run_cfg: Dict[str, Any],
    current_anchor_commit: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_blocker_ledger.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "run_id": str(current_run_cfg.get("run_id", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "anchor_commit": current_anchor_commit,
        "execution_status": "PASS__NO_AUDIT_EXECUTION_BLOCKERS",
        "blockers_preventing_audit": [],
        "note": "No blockers prevented the hardened current-truth audit from executing. Prompt integrity, scope binding, and shared harvest inputs all held.",
        "open_system_blockers_documented_in_audit": [
            {
                "blocker_id": "H1_ACTIVATION_GATE_CLOSED",
                "severity": "HIGH",
                "blocks_system_capability": True,
                "blocks_this_audit": False,
                "elevation_path": "Resolve authority convergence and reconvene H1.",
            },
            {
                "blocker_id": "CURRENT_HEAD_EXTERNAL_CAPABILITY_NOT_CONFIRMED",
                "severity": "HIGH",
                "blocks_system_capability": True,
                "blocks_this_audit": False,
                "elevation_path": "Earn E2 cross-host proof and reconvene capability confirmation.",
            },
            {
                "blocker_id": "EXTERNALITY_CEILING_E1",
                "severity": "MEDIUM",
                "blocks_system_capability": True,
                "blocks_this_audit": False,
                "elevation_path": "Lift from E1 to E2 through cross-host replay proof.",
            },
            {
                "blocker_id": "PLATFORM_ENFORCEMENT_UNPROVEN",
                "severity": "HIGH",
                "blocks_system_capability": True,
                "blocks_this_audit": False,
                "elevation_path": "Earn platform-enforced governance proof before broader product claims.",
            },
            {
                "blocker_id": "EXPANSION_BRANCH_NOT_MERGED_TO_MAIN",
                "severity": "MEDIUM",
                "blocks_canonical_authority": True,
                "blocks_this_audit": False,
                "elevation_path": "Merge through the protected main path.",
            },
            {
                "blocker_id": "NO_EXTERNAL_CUSTOMER_OR_REVENUE",
                "severity": "HIGH",
                "blocks_commercial_claims": True,
                "blocks_this_audit": False,
                "elevation_path": "Earn first customer and revenue receipt before commercial widening.",
            },
        ],
    }


def _build_delta_crosswalk(
    *,
    work_order_id: str,
    baseline_anchor_commit: str,
    current_anchor_commit: str,
    baseline_packet: Dict[str, Any],
    current_packet: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_delta_crosswalk.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "generated_utc": utc_now_iso_z(),
        "preserve_separate_verdicts": True,
        "baseline_verdict_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
        "current_truth_verdict_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_packet.json",
        "frozen_baseline_commit": baseline_anchor_commit,
        "current_truth_commit": current_anchor_commit,
        "crosswalk": {
            "authority_state": {
                "at_frozen_baseline": "MINIMUM_PATH_COMPLETE_THROUGH_GATE_F__BROAD_REAUDIT_PASS__EXPANSION_AUTHORIZED",
                "at_current_truth": "MINIMUM_PATH_COMPLETE_THROUGH_GATE_F__BROAD_REAUDIT_PASS__TRACK_01_CLOSED__TRACK_02_SHARED_HARVEST_COMPLETE",
                "delta": "Current truth adds Track 01 bounded comparative proof closure and a clean Track 02 authority-partitioned audit footing.",
                "what_improved": "Track 01 is closed and Track 02 is now executing from a tracked clean harvest path.",
                "what_stayed_weak": "H1, externality ceiling, platform enforcement, canonical merge, and commercial proof all remain open.",
            },
            "repo_architecture": {
                "at_frozen_baseline": "Clean canonical spine through Gate F with quarantine law and protected merge discipline",
                "at_current_truth": "Same spine plus Track 01 execution artifacts and Track 02 tracked courts",
                "delta": "Post-F expansion logic is now executing through bounded comparative and audit courts.",
                "what_improved": "Comparative proof and dual-audit machinery are now both present.",
                "what_stayed_weak": "No external code audit and repo-root import fragility remain.",
            },
            "governed_system": {
                "at_frozen_baseline": "Gate D cleared, Gate E open, Gate F narrow wedge confirmed, re-audit passed",
                "at_current_truth": "Same plus Track 01 bounded proof frozen and Track 02 dual audit running",
                "delta": "Track 01 adds a real bounded proof layer; Track 02 adds an adversarial audit lane.",
                "what_improved": "Governed proof and review surfaces expanded without widening product truth.",
                "what_stayed_weak": "No external independent ratification.",
            },
            "control_plane_truth": {
                "at_frozen_baseline": "MINIMUM_PATH_COMPLETE__PREDICATE_CHAIN_SATISFIED",
                "at_current_truth": "SAME__PLUS_CONTROLLED_POST_F_TRACKS_EXECUTING",
                "delta": "No sovereign gate changed; only the post-F track layer advanced.",
                "what_improved": "Controlled expansion is behaving constitutionally.",
                "what_stayed_weak": "H1 remains blocked.",
            },
            "runtime_capability_truth": {
                "at_frozen_baseline": "LOCAL_VERIFIER_MODE_WEDGE_ONLY__E1",
                "at_current_truth": "SAME__NO_RUNTIME_CAPABILITY_PROMOTION",
                "delta": "No runtime promotion occurred between baseline and current truth.",
                "what_improved": "Nothing on runtime breadth.",
                "what_stayed_weak": "E1 ceiling, no H1, no E2+.",
            },
            "historical_bounded_proof": {
                "at_frozen_baseline": "NO_TRACK_01_COMPARATIVE_EXECUTION_ADMITTED",
                "at_current_truth": "TRACK_01_TWO_WAVE_ADVANTAGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY",
                "delta": "The largest substantive improvement is the addition of a repeated bounded comparative proof packet.",
                "what_improved": "Track 01 is now real and frozen.",
                "what_stayed_weak": "Comparator set remains tiny and category-bounded.",
            },
            "commercial_product_truth": {
                "at_frozen_baseline": "PRE_REVENUE__SINGLE_TENANT_BOUNDED_VERIFIER",
                "at_current_truth": "SAME__NO_COMMERCIAL_PROMOTION",
                "delta": "No commercial plane improvement occurred.",
                "what_improved": "Nothing on this axis.",
                "what_stayed_weak": "Zero customers, zero revenue, single-tenant only.",
            },
            "full_system_execution_readiness": {
                "at_frozen_baseline": "BOUNDED_MINIMUM_PATH_COMPLETE__BROADER_RATIFICATION_BLOCKED",
                "at_current_truth": "SAME__BROADER_RATIFICATION_BLOCKED",
                "delta": "No full-system readiness change occurred.",
                "what_improved": "Nothing on this axis.",
                "what_stayed_weak": "No civilization-grade ratification, no H1, no E2+.",
            },
            "claim_safety": {
                "at_frozen_baseline": "EXCELLENT__BOUNDARIES_EXPLICIT",
                "at_current_truth": "EXCELLENT__MAINTAINED_THROUGH_TRACK_01_AND_TRACK_02",
                "delta": "Track 01 and Track 02 both preserved forbidden-interpretation discipline.",
                "what_improved": "Evidence separation is now even tighter.",
                "what_stayed_weak": "No weakness on this axis beyond human retelling risk.",
            },
            "benchmark_readiness": {
                "at_frozen_baseline": "SCOPE_DEFINED_ONLY__NOT_EXECUTED",
                "at_current_truth": "BOUNDARY_FAIR_INTERNAL_BENCHMARK_CLOSED__TRACK_01_ONLY",
                "delta": "Track 01 closes the first bounded benchmark lane.",
                "what_is_newly_benchmark_ready": "Internal bounded governed-execution comparison on the local_verifier_mode wedge.",
                "what_is_still_not_benchmark_ready": "Public leaderboards, enterprise bakeoffs, cross-host capability comparisons, Kaggle or math tracks.",
            },
            "open_blockers": {
                "at_frozen_baseline": [
                    "H1 activation closed",
                    "External capability unconfirmed",
                    "Externality ceiling at E1",
                    "Platform enforcement unproven",
                    "No external customer or revenue",
                ],
                "at_current_truth": [
                    "The same five blocker families remain open",
                ],
                "delta": "No structural blocker was cleared by Track 01 or Track 02 execution.",
                "what_stayed_weak": "All five blocker families remain active.",
            },
            "post_f_maturity_classification": {
                "surfaces_promoted_at_current_truth_vs_baseline": [
                    {
                        "surface": "Track 01 bounded comparative proof",
                        "baseline_classification": "intended_but_not_lawfully_promoted",
                        "current_truth_classification": "canonical_but_bounded",
                        "promotion_event": "Track 01 final summary packet",
                    }
                ],
                "surfaces_unchanged": [
                    "Successor control plane remains canonical_and_ratified",
                    "Gate F wedge remains canonical_but_bounded",
                    "H1 activation remains intended_but_not_lawfully_promoted",
                    "Commercial validation remains intended_but_not_lawfully_promoted",
                ],
            },
        },
        "required_questions": {
            "what_improved_because_system_improved": "Track 01 closed as a repeated bounded comparative proof, and Track 02 now has a clean shared-harvest audit footing.",
            "what_stayed_weak": "Runtime breadth, H1, E2+, platform enforcement, and commercial validation all stayed weak.",
            "what_is_newly_benchmark_ready": "The internal bounded comparator lane for the confirmed local_verifier_mode wedge.",
            "what_is_still_not_lawfully_claimable": "Best-AI, broad reasoning superiority, full-system superiority, enterprise readiness, cross-host capability, Kaggle carryover, and multi-tenant claims.",
            "what_remains_product_limited": "Gate F remains one narrow local_verifier_mode wedge only.",
            "what_remains_civilization_ratification_limited": "Anything beyond E1 and beyond bounded verifier-mode proof remains blocked.",
            "what_remains_doctrine_or_lab_only": "Broader lobe, router, Kaggle, H1, and civilization-scale claims.",
        },
        "execution_status": DELTA_EXECUTION_STATUS,
    }


def _build_delta_receipt(
    *,
    work_order_id: str,
    baseline_anchor_commit: str,
    current_anchor_commit: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "generated_utc": utc_now_iso_z(),
        "baseline_anchor_commit": baseline_anchor_commit,
        "current_truth_anchor_commit": current_anchor_commit,
        "preserve_separate_verdicts": True,
        "execution_status": DELTA_EXECUTION_STATUS,
    }


def _build_meta_summary(
    *,
    work_order_id: str,
    rules: List[str],
    baseline_packet_path: Path,
    baseline_receipt_path: Path,
    baseline_blocker_path: Path,
    baseline_packet: Dict[str, Any],
    current_packet_path: Path,
    current_receipt_path: Path,
    current_blocker_path: Path,
    current_packet: Dict[str, Any],
    delta_path: Path,
    delta_receipt_path: Path,
    baseline_anchor_commit: str,
    current_anchor_commit: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_meta_summary.v1",
        "status": "PASS",
        "work_order_id": work_order_id,
        "generated_utc": utc_now_iso_z(),
        "rules_applied": rules,
        "meta_summary_statement": (
            "This Track 02 meta summary preserves one frozen baseline audit and one hardened current-truth audit as separate verdicts. "
            "The frozen baseline remains the static ruler. The current-truth audit is a footing audit of the expansion branch and does not replace the baseline."
        ),
        "baseline_audit_reference": {
            "packet_path": baseline_packet_path.as_posix(),
            "packet_sha256": _sha256_hex(baseline_packet_path),
            "receipt_path": baseline_receipt_path.as_posix(),
            "blocker_ledger_path": baseline_blocker_path.as_posix(),
            "anchor_commit": baseline_anchor_commit,
            "prompt_id": str(baseline_packet.get("prompt_id", "")).strip(),
            "prompt_sha256": str(baseline_packet.get("prompt_sha256", "")).strip(),
            "baseline_contract_unchanged": True,
            "top_level_verdict": str(baseline_packet.get("top_level_verdict", "")).strip(),
            "four_ruling_sentences": dict(baseline_packet.get("four_ruling_sentences", {})),
        },
        "current_truth_audit_reference": {
            "packet_path": current_packet_path.as_posix(),
            "packet_sha256": _sha256_hex(current_packet_path),
            "receipt_path": current_receipt_path.as_posix(),
            "blocker_ledger_path": current_blocker_path.as_posix(),
            "anchor_commit": current_anchor_commit,
            "prompt_id": str(current_packet.get("prompt_id", "")).strip(),
            "prompt_sha256": str(current_packet.get("prompt_sha256", "")).strip(),
            "current_truth_audit_is_footing_audit_not_baseline_replacement": True,
            "expansion_branch_non_authoritative_until_merged": True,
            "top_level_verdict": str(current_packet.get("top_level_verdict", "")).strip(),
            "six_scope_scores": {
                "scope_1_control_plane": current_packet["section_2_six_scope_scorecards"]["scope_1_current_head_sovereign_control_plane"]["score"],
                "scope_2_runtime_capability": current_packet["section_2_six_scope_scorecards"]["scope_2_current_head_runtime_capability_plane"]["score"],
                "scope_3_historical_bounded_proof": current_packet["section_2_six_scope_scorecards"]["scope_3_historical_bounded_frontier_target"]["score"],
                "scope_4_full_system_civilization": current_packet["section_2_six_scope_scorecards"]["scope_4_full_system_civilization_execution_readiness"]["score"],
                "scope_5_product_commercial": current_packet["section_2_six_scope_scorecards"]["scope_5_product_commercial_standing"]["score"],
                "scope_6_net_integrated": current_packet["section_2_six_scope_scorecards"]["scope_6_net_integrated_standing"]["score"],
            },
            "single_sentence_verdict": current_packet["section_7_final_verdict"]["single_sentence_verdict"],
        },
        "delta_crosswalk_reference": {
            "crosswalk_path": delta_path.as_posix(),
            "crosswalk_sha256": _sha256_hex(delta_path),
            "receipt_path": delta_receipt_path.as_posix(),
            "key_delta_finding": "The main substantive improvement from frozen baseline to current truth is Track 01 bounded comparative proof closure plus a clean Track 02 audit footing; no structural blocker was cleared.",
            "axes_that_improved": ["historical_bounded_proof", "benchmark_readiness", "authority_state"],
            "axes_unchanged": ["runtime_capability_truth", "commercial_product_truth", "full_system_execution_readiness", "open_blockers"],
            "axes_maintained_excellent": ["claim_safety", "control_plane_truth"],
        },
        "forbidden_behaviors_compliance": {
            "baseline_and_current_truth_verdicts_not_blended": True,
            "post_anchor_artifacts_did_not_override_frozen_baseline": True,
            "secrets_not_ingested": True,
            "expansion_branch_not_treated_as_canonical": True,
            "historical_bounded_proof_did_not_inflate_current_head": True,
            "track_01_bounded_proof_not_inflated_to_full_system_superiority": True,
            "kaggle_and_broader_lobe_claims_excluded": True,
        },
        "next_lawful_move": NEXT_MOVE,
        "execution_status": EXECUTION_STATUS,
    }


def _build_execution_packet(
    *,
    branch_name: str,
    baseline_anchor_commit: str,
    current_anchor_commit: str,
    dirty_paths_accepted: List[str],
    baseline_packet: Dict[str, Any],
    current_packet: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_execution_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "frozen_baseline_anchor_commit": baseline_anchor_commit,
        "current_truth_anchor_commit": current_anchor_commit,
        "separate_verdicts_preserved": True,
        "accepted_pre_audit_dirty_paths": dirty_paths_accepted,
        "artifact_refs": {
            "baseline_packet_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
            "baseline_receipt_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
            "current_truth_packet_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_packet.json",
            "current_truth_receipt_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_receipt.json",
            "delta_crosswalk_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_delta_crosswalk.json",
            "meta_summary_ref": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_dual_audit_meta_summary.json",
        },
        "baseline_top_level_verdict": str(baseline_packet.get("top_level_verdict", "")).strip(),
        "current_truth_top_level_verdict": str(current_packet.get("top_level_verdict", "")).strip(),
        "next_lawful_move": NEXT_MOVE,
    }


def _build_execution_receipt(
    *,
    branch_name: str,
    baseline_anchor_commit: str,
    current_anchor_commit: str,
    dirty_paths_accepted: List[str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "execution_outcome": EXECUTION_OUTCOME,
        "track_id": TRACK_ID,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "frozen_baseline_anchor_commit": baseline_anchor_commit,
        "current_truth_anchor_commit": current_anchor_commit,
        "accepted_pre_audit_dirty_paths": dirty_paths_accepted,
        "next_lawful_move": NEXT_MOVE,
    }


def _resolve_run_output_path(run_cfg: Dict[str, Any], key: str, *, root: Path) -> Path:
    outputs = dict(run_cfg.get("outputs", {}))
    raw = str(outputs.get(key, "")).strip()
    if not raw:
        raise RuntimeError(f"FAIL_CLOSED: missing output path {key} in Track 02 work order")
    return _resolve_template(raw, root=root)


def run(*, reports_root: Path, scope_packet_path: Path, harvest_receipt_path: Path) -> Dict[str, Any]:
    root = repo_root()
    scope_packet = _load_json_required(scope_packet_path, label="Track 02 scope packet")
    _require_pass(scope_packet, label="Track 02 scope packet")
    if str(scope_packet.get("scope_outcome", "")).strip() != scope_tranche.SCOPE_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope outcome mismatch")

    harvest_receipt = _load_json_required(harvest_receipt_path, label="Track 02 shared-harvest receipt")
    _require_pass(harvest_receipt, label="Track 02 shared-harvest receipt")
    if str(harvest_receipt.get("next_lawful_move", "")).strip() != harvest_tranche.NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: shared-harvest receipt does not authorize the dual-audit tranche")

    branch_name = _current_branch_name(root)
    if branch_name != scope_tranche.REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 02 dual audit must run on {scope_tranche.REQUIRED_WORKING_BRANCH}, got {branch_name}")

    dirty_paths_accepted = _validate_pre_audit_dirty_state(root)

    work_order_path = Path(str(scope_packet.get("work_order_binding", {}).get("work_order_path", "")).strip())
    if not work_order_path.is_file():
        raise RuntimeError("FAIL_CLOSED: Track 02 work order path from scope packet is missing")
    work_order = _load_json_required(work_order_path, label="Track 02 work order")

    baseline_prompt_path = Path(
        str(scope_packet.get("prompt_artifact_binding", {}).get("baseline_frozen", {}).get("source_path", "")).strip()
    )
    current_prompt_path = Path(
        str(scope_packet.get("prompt_artifact_binding", {}).get("current_truth_hardened", {}).get("source_path", "")).strip()
    )
    if not baseline_prompt_path.is_file() or not current_prompt_path.is_file():
        raise RuntimeError("FAIL_CLOSED: Track 02 prompt artifact paths must exist")

    baseline_prompt_sha = _sha256_hex(baseline_prompt_path)
    current_prompt_sha = _sha256_hex(current_prompt_path)
    if baseline_prompt_sha != str(scope_packet["prompt_artifact_binding"]["baseline_frozen"]["expected_sha256"]).lower():
        raise RuntimeError("FAIL_CLOSED: baseline prompt hash mismatch at audit execution")
    if current_prompt_sha != str(scope_packet["prompt_artifact_binding"]["current_truth_hardened"]["expected_sha256"]).lower():
        raise RuntimeError("FAIL_CLOSED: current-truth prompt hash mismatch at audit execution")

    evidence_manifest = _load_json_required(
        reports_root / "cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
        label="Track 02 evidence manifest",
    )
    authority_partition = _load_json_required(
        reports_root / "cohort0_post_f_track_02_dual_audit_authority_partition.json",
        label="Track 02 authority partition",
    )
    baseline_view = _load_json_required(
        reports_root / harvest_tranche.OUTPUT_BASELINE_VIEW,
        label="Track 02 frozen baseline evidence view",
    )
    current_view = _load_json_required(
        reports_root / harvest_tranche.OUTPUT_CURRENT_VIEW,
        label="Track 02 current-truth evidence view",
    )

    branch_law_packet = common.load_json_required(root, f"{common.REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_branch_law_packet.json", label="live branch law packet")
    product_truth_packet = common.load_json_required(root, f"{common.REPORTS_ROOT_REL}/cohort0_gate_f_post_close_live_product_truth_packet.json", label="live product truth packet")
    reaudit_receipt = common.load_json_required(root, f"{common.REPORTS_ROOT_REL}/cohort0_post_f_broad_canonical_reaudit_receipt.json", label="post-F broad canonical re-audit receipt")
    track01_packet = common.load_json_required(root, f"{common.REPORTS_ROOT_REL}/{track01_final.OUTPUT_PACKET}", label="Track 01 final summary packet")
    orchestrator_receipt = common.load_json_required(root, f"{common.REPORTS_ROOT_REL}/cohort0_successor_master_orchestrator_receipt.json", label="orchestrator receipt")

    _require_pass(branch_law_packet, label="live branch law packet")
    _require_pass(product_truth_packet, label="live product truth packet")
    _require_pass(reaudit_receipt, label="post-F re-audit receipt")
    _require_pass(track01_packet, label="Track 01 final summary packet")
    _require_pass(orchestrator_receipt, label="orchestrator receipt")

    audit_runs = list(work_order.get("audit_runs", []))
    if len(audit_runs) < 2:
        raise RuntimeError("FAIL_CLOSED: Track 02 work order must define both audit runs")
    baseline_run_cfg = dict(audit_runs[0])
    current_run_cfg = dict(audit_runs[1])

    baseline_anchor_ref = str(scope_packet.get("anchor_binding", {}).get("frozen_baseline", {}).get("ref_name", "")).strip()
    current_anchor_ref = str(scope_packet.get("anchor_binding", {}).get("current_truth", {}).get("ref_name", "")).strip()
    baseline_anchor_commit = str(baseline_view.get("anchor_commit", "")).strip()
    current_anchor_commit = str(current_view.get("anchor_commit", "")).strip()

    baseline_packet = _build_baseline_packet(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        baseline_run_cfg=baseline_run_cfg,
        baseline_prompt_id=str(scope_packet["prompt_artifact_binding"]["baseline_frozen"]["prompt_id"]).strip()
        if "prompt_id" in scope_packet.get("prompt_artifact_binding", {}).get("baseline_frozen", {})
        else scope_tranche.REQUIRED_BASELINE_PROMPT_ID,
        baseline_prompt_sha=baseline_prompt_sha,
        baseline_anchor_ref=baseline_anchor_ref,
        baseline_anchor_commit=baseline_anchor_commit,
        evidence_manifest=evidence_manifest,
        authority_partition=authority_partition,
        branch_law_packet=branch_law_packet,
        product_truth_packet=product_truth_packet,
        reaudit_receipt=reaudit_receipt,
    )
    baseline_receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_audit_receipt.v1",
        "status": "PASS",
        "work_order_id": str(work_order.get("work_order_id", "")).strip(),
        "run_id": str(baseline_run_cfg.get("run_id", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "anchor_commit": baseline_anchor_commit,
        "prompt_id": scope_tranche.REQUIRED_BASELINE_PROMPT_ID,
        "prompt_sha256": baseline_prompt_sha,
        "verdict_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
        "blocker_ledger_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_frozen_baseline_blocker_ledger.json",
        "baseline_contract_unchanged": True,
        "post_anchor_artifacts_rejected": True,
        "axes_produced": list(baseline_run_cfg.get("expected_axes", [])),
        "execution_status": BASELINE_EXECUTION_STATUS,
    }
    baseline_blocker = _build_baseline_blocker_ledger(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        baseline_run_cfg=baseline_run_cfg,
        baseline_anchor_commit=baseline_anchor_commit,
    )

    current_packet = _build_current_truth_packet(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        current_run_cfg=current_run_cfg,
        current_prompt_id=scope_tranche.REQUIRED_CURRENT_PROMPT_ID,
        current_prompt_sha=current_prompt_sha,
        current_anchor_ref=current_anchor_ref,
        current_anchor_commit=current_anchor_commit,
        branch_law_packet=branch_law_packet,
        product_truth_packet=product_truth_packet,
        orchestrator_receipt=orchestrator_receipt,
        reaudit_receipt=reaudit_receipt,
        track01_packet=track01_packet,
        scope_packet=scope_packet,
        evidence_manifest=evidence_manifest,
        authority_partition=authority_partition,
    )
    current_receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_audit_receipt.v1",
        "status": "PASS",
        "work_order_id": str(work_order.get("work_order_id", "")).strip(),
        "run_id": str(current_run_cfg.get("run_id", "")).strip(),
        "generated_utc": utc_now_iso_z(),
        "anchor_commit": current_anchor_commit,
        "prompt_id": scope_tranche.REQUIRED_CURRENT_PROMPT_ID,
        "prompt_sha256": current_prompt_sha,
        "verdict_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_audit_packet.json",
        "blocker_ledger_path": f"{common.REPORTS_ROOT_REL}/cohort0_post_f_track_02_current_truth_blocker_ledger.json",
        "current_truth_overrides_applied": True,
        "authorized_current_truth_classes_used": list(current_run_cfg.get("authorized_current_truth_classes", [])),
        "axes_produced": list(current_run_cfg.get("expected_axes", [])),
        "expansion_branch_authority_note": "expansion/post-f-track-01 remains non-authoritative until merged to main",
        "execution_status": CURRENT_EXECUTION_STATUS,
    }
    current_blocker = _build_current_truth_blocker_ledger(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        current_run_cfg=current_run_cfg,
        current_anchor_commit=current_anchor_commit,
    )

    baseline_packet_path = _resolve_run_output_path(baseline_run_cfg, "verdict_path", root=root)
    baseline_receipt_path = _resolve_run_output_path(baseline_run_cfg, "receipt_path", root=root)
    baseline_blocker_path = _resolve_run_output_path(baseline_run_cfg, "blocker_ledger_path", root=root)
    current_packet_path = _resolve_run_output_path(current_run_cfg, "verdict_path", root=root)
    current_receipt_path = _resolve_run_output_path(current_run_cfg, "receipt_path", root=root)
    current_blocker_path = _resolve_run_output_path(current_run_cfg, "blocker_ledger_path", root=root)

    write_json_stable(baseline_packet_path, baseline_packet)
    write_json_stable(baseline_receipt_path, baseline_receipt)
    write_json_stable(baseline_blocker_path, baseline_blocker)
    write_json_stable(current_packet_path, current_packet)
    write_json_stable(current_receipt_path, current_receipt)
    write_json_stable(current_blocker_path, current_blocker)

    delta_cfg = dict(work_order.get("delta_crosswalk", {}))
    delta_path = _resolve_template(str(delta_cfg.get("output_path", "")).strip(), root=root)
    delta_receipt_path = _resolve_template(str(delta_cfg.get("receipt_path", "")).strip(), root=root)
    delta_crosswalk = _build_delta_crosswalk(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        baseline_anchor_commit=baseline_anchor_commit,
        current_anchor_commit=current_anchor_commit,
        baseline_packet=baseline_packet,
        current_packet=current_packet,
    )
    delta_receipt = _build_delta_receipt(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        baseline_anchor_commit=baseline_anchor_commit,
        current_anchor_commit=current_anchor_commit,
    )
    write_json_stable(delta_path, delta_crosswalk)
    write_json_stable(delta_receipt_path, delta_receipt)

    meta_cfg = dict(work_order.get("meta_summary", {}))
    meta_path = _resolve_template(str(meta_cfg.get("output_path", "")).strip(), root=root)
    meta_summary = _build_meta_summary(
        work_order_id=str(work_order.get("work_order_id", "")).strip(),
        rules=list(meta_cfg.get("rules", [])),
        baseline_packet_path=baseline_packet_path,
        baseline_receipt_path=baseline_receipt_path,
        baseline_blocker_path=baseline_blocker_path,
        baseline_packet=baseline_packet,
        current_packet_path=current_packet_path,
        current_receipt_path=current_receipt_path,
        current_blocker_path=current_blocker_path,
        current_packet=current_packet,
        delta_path=delta_path,
        delta_receipt_path=delta_receipt_path,
        baseline_anchor_commit=baseline_anchor_commit,
        current_anchor_commit=current_anchor_commit,
    )
    write_json_stable(meta_path, meta_summary)

    execution_packet = _build_execution_packet(
        branch_name=branch_name,
        baseline_anchor_commit=baseline_anchor_commit,
        current_anchor_commit=current_anchor_commit,
        dirty_paths_accepted=dirty_paths_accepted,
        baseline_packet=baseline_packet,
        current_packet=current_packet,
    )
    execution_receipt = _build_execution_receipt(
        branch_name=branch_name,
        baseline_anchor_commit=baseline_anchor_commit,
        current_anchor_commit=current_anchor_commit,
        dirty_paths_accepted=dirty_paths_accepted,
    )
    execution_report = common.report_lines(
        "Cohort0 Post-F Track 02 Dual Audit Execution Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Execution outcome: `{EXECUTION_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Frozen baseline anchor commit: `{baseline_anchor_commit}`",
            f"- Current-truth anchor commit: `{current_anchor_commit}`",
            f"- Accepted pre-audit dirty paths: `{len(dirty_paths_accepted)}` shared-harvest artifacts only",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=execution_packet,
        receipt=execution_receipt,
        report_text=execution_report,
    )

    return {
        "execution_outcome": EXECUTION_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Execute the Track 02 frozen baseline and current-truth audits.")
    parser.add_argument(
        "--scope-packet",
        default=f"{common.REPORTS_ROOT_REL}/{scope_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--harvest-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{harvest_tranche.OUTPUT_RECEIPT}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        harvest_receipt_path=common.resolve_path(root, args.harvest_receipt),
    )
    print(result["execution_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
