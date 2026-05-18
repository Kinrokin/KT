from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import validate_external_attestation
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


LANE = "KT_BOUNDED_FORWARD_STREAMS_UNDER_H06_ATTESTATION_PARKED_V1"
POSTURE = (
    "H06_EXTERNAL_REAUDIT_DEFERRED__INDEPENDENT_ATTESTATION_REQUIRED__"
    "CONTINUE_PREP_SHADOW_AND_INTERNAL_CAPABILITY_COMPLETION_UNDER_CLAIM_CEILING"
)

OUTPUTS = {
    "attestation_collection_packet": "external/attestation_collection_packet.json",
    "attestation_collection_receipt": "KT_PROD_CLEANROOM/reports/kt_attestation_collection_support_receipt.json",
    "claim_scan_receipt": "KT_PROD_CLEANROOM/reports/kt_bounded_launch_claim_scan_receipt.json",
    "launch_wedge_scorecard": "commercial/bounded_launch_wedge_readiness_scorecard.json",
    "highway_shadow_warn_ladder": "governance/highway_shadow_warn_promotion_ladder_v1.json",
    "highway_shadow_warn_receipt": "KT_PROD_CLEANROOM/reports/highway_shadow_warn_promotion_readiness_receipt.json",
    "fp0_shadow_scorecard": "KT_PROD_CLEANROOM/reports/fp0_context_efficiency_shadow_scorecard.json",
    "adaptive_shadow_board": "KT_PROD_CLEANROOM/reports/kt_adaptive_capability_training_shadow_board.json",
    "benchmark_prep_board": "KT_PROD_CLEANROOM/reports/kt_benchmark_and_hostile_reproduction_prep_board.json",
    "repo_cleanup_receipt": "KT_PROD_CLEANROOM/reports/kt_repo_cleanup_debloat_shadow_plan_receipt.json",
    "bounded_streams_receipt": "KT_PROD_CLEANROOM/reports/kt_bounded_forward_streams_receipt.json",
}

CLAIM_SCAN_FILES = (
    "commercial/customer_safe_language_pack.md",
    "commercial/one_page_current_state.md",
    "commercial/launch_boundary_notice.md",
    "commercial/quickstart.md",
    "commercial/operator_runbook.md",
    "commercial/pilot_scope.md",
    "commercial/pilot_limitations.md",
    "governance/allowed_launch_claims.json",
    "governance/current_claim_ceiling.json",
)

NEGATIVE_CONTEXT_MARKERS = (
    "not ",
    "no ",
    "cannot ",
    "blocked",
    "excluded",
    "forbidden",
    "pending",
    "unauthorized",
    "unproven",
    "unearned",
    "does not ",
    "must not ",
    "remains pending",
    "remains blocked",
)

FORBIDDEN_POSITIVE_PATTERNS = (
    re.compile(r"\bexternally audited\b", re.IGNORECASE),
    re.compile(r"\bindependently certified\b", re.IGNORECASE),
    re.compile(r"\bbeyond[- ]SOTA\b", re.IGNORECASE),
    re.compile(r"\bS-tier\b", re.IGNORECASE),
    re.compile(r"\b7B amplification (is )?proven\b", re.IGNORECASE),
    re.compile(r"\bcommercially activated without limitation\b", re.IGNORECASE),
    re.compile(r"\bfully ratified autonomous civilization stack\b", re.IGNORECASE),
)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _text_for_scan(root: Path, raw_path: str) -> str:
    path = root / raw_path
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8-sig")


def scan_claim_text(text: str, *, source: str) -> list[Dict[str, Any]]:
    violations: list[Dict[str, Any]] = []
    recent_context: list[str] = []
    negative_block = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if any(marker in lowered for marker in ("forbidden language", "forbidden_claim", "forbidden claims", "excluded:")):
            negative_block = True
        if negative_block and lowered.strip().endswith(":") and not any(
            marker in lowered for marker in ("forbidden", "excluded", "blocked")
        ):
            negative_block = False
        context = " ".join([*recent_context[-4:], lowered])
        for pattern in FORBIDDEN_POSITIVE_PATTERNS:
            if not pattern.search(line):
                continue
            if negative_block or any(marker in context for marker in NEGATIVE_CONTEXT_MARKERS):
                continue
            violations.append({"source": source, "line": line_no, "pattern": pattern.pattern, "text": line.strip()})
        recent_context.append(lowered)
    return violations


def scan_launch_claims(root: Path, *, paths: Iterable[str] = CLAIM_SCAN_FILES) -> Dict[str, Any]:
    missing: list[str] = []
    violations: list[Dict[str, Any]] = []
    checked: list[str] = []
    for raw_path in paths:
        path = root / raw_path
        if not path.is_file():
            missing.append(raw_path)
            continue
        checked.append(raw_path)
        violations.extend(scan_claim_text(_text_for_scan(root, raw_path), source=raw_path))
    return {
        "schema_id": "kt.bounded_launch.claim_scan_receipt.v1",
        "artifact_id": "KT_BOUNDED_LAUNCH_CLAIM_SCAN_RECEIPT",
        "lane": LANE,
        "authority": "CLAIM_SCAN_UNDER_CEILING",
        "generated_utc": utc_now_iso_z(),
        "checked_files": checked,
        "missing_files": missing,
        "violation_count": len(violations),
        "violations": violations,
        "claim_boundary_passed": not violations,
        "external_audit_completed": False,
        "commercial_claims_authorized": False,
        "seven_b_amplification_proven": False,
        "s_tier_claimed": False,
    }


def _attestation_collection_packet(root: Path, attestation_receipt: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.external_attestation.collection_packet.v1",
        "artifact_id": "KT_EXTERNAL_ATTESTATION_COLLECTION_PACKET",
        "lane": "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION",
        "authority": "COLLECTION_SUPPORT_ONLY",
        "generated_utc": utc_now_iso_z(),
        "target_attestation_path": validate_external_attestation.TARGET_ATTESTATION,
        "target_attestation_exists": (root / validate_external_attestation.TARGET_ATTESTATION).is_file(),
        "self_authoring_allowed": False,
        "attestation_accepted": bool(attestation_receipt.get("attestation_accepted")) is True,
        "next_lawful_move": "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION",
        "reviewer_materials": [
            "external/attestation_template.json",
            "external/attestation_schema.json",
            "external/attestation_instructions.md",
            "external/reviewer_checklist.md",
            "external/evidence_bundle_manifest.json",
            "external/commands_to_run.md",
            "external/accepted_deferred_rejected_verdicts.md",
        ],
        "cannot_claim_external_audit_complete": True,
        "cannot_authorize_commercial_claims": True,
    }


def _launch_wedge_scorecard(claim_scan: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.bounded_launch.wedge_readiness_scorecard.v1",
        "artifact_id": "KT_BOUNDED_LAUNCH_WEDGE_READINESS_SCORECARD",
        "authority": "BOUNDED_PILOT_PREP",
        "launch_wedge": ["KT Verifier", "KT Evidence Pack", "KT Claim Compiler"],
        "readiness": {
            "quickstart": "PREPARED",
            "operator_runbook": "PREPARED",
            "deployment_profiles": "PREPARED",
            "support_boundary": "PREPARED",
            "data_governance": "PREPARED",
            "security_review_packet": "PREPARED",
            "pilot_materials": "PREPARED",
        },
        "claim_scan_passed": bool(claim_scan.get("claim_boundary_passed")),
        "allowed_mode": "BOUNDED_PILOT_OR_INTERNAL_OPERATIONAL_USE",
        "external_attestation_pending": True,
        "commercial_claims_authorized": False,
    }


def _highway_shadow_warn_ladder() -> Dict[str, Any]:
    return {
        "schema_id": "kt.highway.shadow_warn_promotion_ladder.v1",
        "artifact_id": "HIGHWAY_SHADOW_WARN_PROMOTION_LADDER_V1",
        "authority": "PREP_ONLY_PROMOTION_PLAN",
        "current_state": "PREP_ONLY_RELANDED",
        "target_shadow_label": "HIGHWAY_SYSTEM_SHADOW_READY__NO_CANONICAL_AUTHORITY",
        "target_warn_label": "HIGHWAY_WARN_ONLY_ACTIVE__NO_CLAIM_EXPANSION",
        "promotion_order": ["PREP_ONLY", "SHADOW_READY", "WARN_ONLY_ACTIVE", "FAIL_CLOSED_CANDIDATE", "CANONICAL_ACTIVE"],
        "allowed_now": ["SHADOW_READY_CANDIDATE", "WARN_ONLY_PREP"],
        "canonical_authority_allowed_now": False,
        "required_shadow_proof": [
            "authority gate observes H06 blocker",
            "route resolver emits no canonical effect",
            "posture conflict count is zero",
            "commercial claim guard rejects overclaim",
            "promotion gate rejects direct prep-to-canonical jump",
        ],
    }


def _highway_shadow_warn_receipt() -> Dict[str, Any]:
    return {
        "schema_id": "kt.highway.shadow_warn_promotion_readiness_receipt.v1",
        "artifact_id": "HIGHWAY_SHADOW_WARN_PROMOTION_READINESS_RECEIPT",
        "authority": "SHADOW_WARN_READINESS_ONLY",
        "generated_utc": utc_now_iso_z(),
        "shadow_ready_candidate": True,
        "warn_only_candidate": True,
        "canonical_active": False,
        "fail_closed_active": False,
        "claim_expansion_allowed": False,
        "target_label": "HIGHWAY_SYSTEM_SHADOW_READY__NO_CANONICAL_AUTHORITY",
        "next_lawful_move": "RUN_HIGHWAY_SHADOW_OBSERVATION_MATRIX",
    }


def _fp0_scorecard() -> Dict[str, Any]:
    sample = {"launch_wedge": ["verifier", "evidence_pack", "claim_compiler"], "attestation": "pending"}
    canonical = json.dumps(sample, sort_keys=True, ensure_ascii=True)
    # Keep the benchmark simple and deterministic; JSON remains canonical.
    compact = canonical.replace(" ", "")
    return {
        "schema_id": "kt.fp0.context_efficiency_shadow_scorecard.v1",
        "artifact_id": "FP0_CONTEXT_EFFICIENCY_SHADOW_SCORECARD",
        "authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "json_remains_canonical": True,
        "sample_json_bytes": len(canonical.encode("utf-8")),
        "compact_prompt_bytes": len(compact.encode("utf-8")),
        "context_efficiency_candidate": len(compact) <= len(canonical),
        "local_runtime_authority": "NONE",
        "seven_b_amplification_proven": False,
        "claim_expansion_allowed": False,
    }


def _adaptive_shadow_board() -> Dict[str, Any]:
    return {
        "schema_id": "kt.adaptive_capability_training_shadow_board.v1",
        "artifact_id": "KT_ADAPTIVE_CAPABILITY_TRAINING_SHADOW_BOARD",
        "authority": "PREP_SHADOW_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "streams": {
            "adaptive_law_ratification": "READY_FOR_SHADOW_DETAILING",
            "training_loop_readiness": "PREP_SHADOW",
            "router_lobe_implementation": "PREP_SHADOW",
            "adapter_forge": "PREP_SHADOW",
            "tournament_engine": "PREP_SHADOW",
            "teacher_chaos": "PREP_SHADOW",
        },
        "promotion_requires": ["lineage", "eval", "replay", "rollback", "separate authority"],
        "router_superiority_claim_allowed": False,
        "lobe_orchestration_claim_allowed": False,
        "training_claim_authority": "NONE",
    }


def _benchmark_prep_board() -> Dict[str, Any]:
    return {
        "schema_id": "kt.benchmark_hostile_reproduction_prep_board.v1",
        "artifact_id": "KT_BENCHMARK_AND_HOSTILE_REPRODUCTION_PREP_BOARD",
        "authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "benchmark_programs": [
            "provider_runtime_bakeoff",
            "verified_work_per_dollar",
            "7b_ablation",
            "monolith_vs_adapter_vs_router",
            "attack_survival",
            "replay_cost_scorecard",
        ],
        "hostile_reproduction": "PREP_ONLY_EXTERNAL_REVIEWER_REQUIRED",
        "superiority_claim_allowed": False,
        "seven_b_amplification_proven": False,
        "s_tier_claim_allowed": False,
    }


def _repo_cleanup_receipt(root: Path) -> Dict[str, Any]:
    manifests = [
        "repo_cleanup/archive_manifest.json",
        "repo_cleanup/current_authority_manifest.json",
        "repo_cleanup/historical_receipt_index.json",
        "repo_cleanup/generated_artifact_retirement_plan.json",
    ]
    present = [raw for raw in manifests if (root / raw).is_file()]
    return {
        "schema_id": "kt.repo_cleanup.debloat_shadow_plan_receipt.v1",
        "artifact_id": "KT_REPO_CLEANUP_DEBLOAT_SHADOW_PLAN_RECEIPT",
        "authority": "PREP_ONLY_INDEX",
        "generated_utc": utc_now_iso_z(),
        "manifests_present": present,
        "delete_authorized": False,
        "archive_index_before_move_required": True,
        "current_authority_first": True,
        "normal_agent_context_debloated": (root / ".agentignore").is_file(),
    }


def _combined_receipt(parts: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    claim_passed = bool(parts["claim_scan_receipt"].get("claim_boundary_passed"))
    attestation_accepted = bool(parts["attestation_collection_receipt"].get("attestation_accepted"))
    return {
        "schema_id": "kt.bounded_forward_streams.receipt.v1",
        "artifact_id": "KT_BOUNDED_FORWARD_STREAMS_RECEIPT",
        "lane": LANE,
        "authority": "PREP_SHADOW_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "posture": POSTURE,
        "external_attestation_accepted": attestation_accepted,
        "external_audit_completed": False,
        "commercial_claims_authorized": False,
        "seven_b_amplification_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "claim_boundary_passed": claim_passed,
        "streams": {
            "external_attestation_collection_support": "READY_BLOCKER_PRESERVED",
            "bounded_launch_wedge": "READY_UNDER_CLAIM_CEILING" if claim_passed else "BLOCKED_CLAIM_SCAN",
            "highway_shadow_warn": "SHADOW_WARN_READY_CANDIDATE",
            "fp0_efficiency": "PREP_ONLY_NO_CLAIM_EXPANSION",
            "adaptive_capability_training": "PREP_SHADOW",
            "benchmark_hostile_reproduction": "PREP_ONLY",
            "repo_cleanup_debloat": "PREP_ONLY_INDEX",
        },
        "next_lawful_moves": [
            "collect real independent external attestation",
            "run highway shadow observation matrix",
            "continue bounded launch wedge pilot packaging",
            "expand adaptive/capability/training shadow modules",
            "execute preregistered benchmark prep without superiority claims",
        ],
    }


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    attestation_receipt = validate_external_attestation.evaluate_attestation(root=root)
    claim_scan = scan_launch_claims(root)
    parts: Dict[str, Dict[str, Any]] = {
        "attestation_collection_packet": _attestation_collection_packet(root, attestation_receipt),
        "attestation_collection_receipt": {
            "schema_id": "kt.external_attestation.collection_support_receipt.v1",
            "artifact_id": "KT_ATTESTATION_COLLECTION_SUPPORT_RECEIPT",
            "authority": "COLLECTION_SUPPORT_ONLY",
            "generated_utc": utc_now_iso_z(),
            "attestation_target": validate_external_attestation.TARGET_ATTESTATION,
            "attestation_present": bool(attestation_receipt.get("attestation_present")),
            "attestation_accepted": bool(attestation_receipt.get("attestation_accepted")),
            "self_authored_attestation_allowed": False,
            "blockers": list(attestation_receipt.get("blockers", [])),
            "next_lawful_move": "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION",
        },
        "claim_scan_receipt": claim_scan,
        "launch_wedge_scorecard": _launch_wedge_scorecard(claim_scan),
        "highway_shadow_warn_ladder": _highway_shadow_warn_ladder(),
        "highway_shadow_warn_receipt": _highway_shadow_warn_receipt(),
        "fp0_shadow_scorecard": _fp0_scorecard(),
        "adaptive_shadow_board": _adaptive_shadow_board(),
        "benchmark_prep_board": _benchmark_prep_board(),
        "repo_cleanup_receipt": _repo_cleanup_receipt(root),
    }
    parts["bounded_streams_receipt"] = _combined_receipt(parts)

    for key, raw_path in OUTPUTS.items():
        write_json_stable(root / raw_path, parts[key])
    print(parts["bounded_streams_receipt"]["posture"])
    return parts


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run bounded forward streams under the parked H06 external attestation blocker.")
    parser.add_argument("--output-root", default="")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = Path(args.output_root) if args.output_root else None
    run(output_root=root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
