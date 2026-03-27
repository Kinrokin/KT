from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.benchmark_constitution_validate import _enforce_write_scope_post, _enforce_write_scope_pre, _maybe_write_json_output
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z


GOV = "KT_PROD_CLEANROOM/governance"
REP = "KT_PROD_CLEANROOM/reports"
PROD = "KT_PROD_CLEANROOM/product"

TRUTH_LOCK = f"{GOV}/current_head_truth_lock.json"
HIST_FIREWALL = f"{GOV}/historical_claim_firewall.json"
W5_BLOCKERS = f"{REP}/kt_wave5_blocker_matrix.json"
W5_TIER = f"{REP}/kt_wave5_final_tier_ruling.json"
W5_READJ = f"{REP}/kt_wave5_final_readjudication_receipt.json"
C006_STATUS = f"{REP}/c006_deferral_status_receipt.json"
HEARTBEAT = f"{REP}/c006_deferral_heartbeat.json"
COMMERCIAL = f"{REP}/commercial_truth_packet.json"
VERIFIER = f"{REP}/public_verifier_kit.json"
C006_KIT = f"{REP}/c006_second_host_kit.json"
PRODUCT_INSTALL = f"{REP}/product_install_15m_receipt.json"
OPERATOR_HANDOFF = f"{REP}/operator_handoff_receipt.json"
STANDARDS = f"{REP}/standards_mapping_receipt.json"
DEPLOY_REPORT = f"{REP}/deployment_profiles.json"
ROUTER_ORDERED = f"{REP}/router_ordered_proof_receipt.json"
ROUTER_SCORE = f"{REP}/router_superiority_scorecard.json"
BASELINE_SCORECARD = f"{REP}/baseline_vs_live_scorecard.json"
BENCHMARK_RECEIPT = f"{REP}/benchmark_constitution_receipt.json"
ALIAS_RETIREMENT = f"{REP}/scorecard_alias_retirement_receipt.json"
DETACHMENT_RECEIPT = f"{REP}/competitive_scorecard_validator_detachment_receipt.json"
E2_RECEIPT = f"{REP}/e2_cross_host_replay_receipt.json"
AUDIT_PACKET = f"{REP}/external_audit_packet_manifest.json"
E1_RECEIPT = f"{REP}/e1_bounded_campaign_receipt.json"

PROD_DEPLOY = f"{PROD}/deployment_profiles.json"
WRAPPER = f"{PROD}/client_wrapper_spec.json"
SUPPORT = f"{PROD}/support_boundary.json"
ONE_PAGE = f"{PROD}/one_page_product_truth_surface.md"
RUNBOOK = f"{PROD}/operator_runbook_v2.md"
NIST = f"{PROD}/nist_mapping_matrix.json"
ISO42001 = f"{PROD}/iso_42001_mapping_matrix.json"
EUAI = f"{PROD}/eu_ai_act_alignment_matrix.json"

OUT_BLOCKERS = f"{GOV}/final_blocker_matrix.json"
OUT_CLAIMS = f"{GOV}/final_claim_class_outcome.json"
OUT_FORBIDDEN = f"{GOV}/final_forbidden_claims_list.json"
OUT_TIER = f"{GOV}/final_tier_ruling.json"
OUT_PRODUCT = f"{PROD}/final_product_truth_boundary.json"
OUT_RECEIPT = f"{REP}/final_current_head_adjudication_receipt.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _j(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required W8 surface: {rel}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected object JSON at {rel}")
    return payload


def _txt(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required W8 text surface: {rel}")
    return path.read_text(encoding="utf-8")


def _all(text: str, needles: Sequence[str]) -> bool:
    lowered = text.lower()
    return all(str(needle).lower() in lowered for needle in needles)


def build_final_blocker_matrix(*, root: Path) -> Dict[str, Any]:
    truth_lock = _j(root, TRUTH_LOCK)
    blockers = _j(root, W5_BLOCKERS)
    c006 = _j(root, C006_STATUS)
    heartbeat = _j(root, HEARTBEAT)
    router_ordered = _j(root, ROUTER_ORDERED)
    router_score = _j(root, ROUTER_SCORE)

    active = []
    for row in blockers.get("open_blockers", []):
        if isinstance(row, dict):
            active.append(
                {
                    "blocker_id": str(row.get("blocker_id", "")).strip(),
                    "blocker_scope": "CURRENT_HEAD_CANONICAL_CLAIM_BLOCKER",
                    "state": str(row.get("state", "")).strip(),
                    "status": str(row.get("deferral_status", "")).strip() or str(row.get("state", "")).strip(),
                    "current_externality_ceiling": str(row.get("current_externality_ceiling", "")).strip(),
                    "comparative_widening": str(row.get("comparative_widening", "")).strip(),
                    "commercial_widening": str(row.get("commercial_widening", "")).strip(),
                    "reentry_condition": str(row.get("reentry_condition", {}).get("description", "")).strip(),
                }
            )

    elevation = [
        {
            "blocker_id": "LEARNED_ROUTER_SUPERIORITY_NOT_EARNED",
            "status": "OPEN" if not bool(router_score.get("superiority_earned")) else "CLOSED",
            "ref": ROUTER_SCORE,
        },
        {
            "blocker_id": "MULTI_LOBE_ORCHESTRATION_NOT_EARNED",
            "status": "OPEN" if not bool(router_ordered.get("multi_lobe_promotion_allowed")) else "CLOSED",
            "ref": ROUTER_ORDERED,
        },
        {
            "blocker_id": "COMPARATIVE_WIDENING_NOT_LAWFUL",
            "status": "OPEN" if str(truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "")).strip() == "FORBIDDEN" else "CLOSED",
            "ref": TRUTH_LOCK,
        },
        {
            "blocker_id": "BROAD_PRODUCT_READINESS_NOT_EARNED",
            "status": "OPEN",
            "ref": PRODUCT_INSTALL,
        },
    ]

    return {
        "schema_id": "kt.final_current_head.blocker_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if str(truth_lock.get("status", "")).strip() == "PASS"
        and str(c006.get("status", "")).strip() == "PASS"
        and str(heartbeat.get("status", "")).strip() == "PASS"
        else "FAIL",
        "claim_boundary": "This matrix separates the one active current-head canonical claim blocker from broader elevation blockers. Historical proof is excluded from this compilation.",
        "historical_uplift_blocked": str(truth_lock.get("historical_claim_firewall_status", "")).strip() == "ACTIVE",
        "machine_effective_state": dict(c006.get("machine_effective_state", {})),
        "active_current_head_claim_blocker_count": len(active),
        "active_current_head_claim_blocker_ids": [row["blocker_id"] for row in active],
        "open_current_head_claim_blockers": active,
        "elevation_blockers": elevation,
        "source_refs": [TRUTH_LOCK, W5_BLOCKERS, C006_STATUS, HEARTBEAT, ROUTER_ORDERED, ROUTER_SCORE],
    }


def build_final_claim_class_outcome(*, root: Path, final_blockers: Dict[str, Any]) -> Dict[str, Any]:
    truth_lock = _j(root, TRUTH_LOCK)
    wave5_tier = _j(root, W5_TIER)
    router_ordered = _j(root, ROUTER_ORDERED)
    router_score = _j(root, ROUTER_SCORE)
    product_install = _j(root, PRODUCT_INSTALL)
    operator_handoff = _j(root, OPERATOR_HANDOFF)
    standards = _j(root, STANDARDS)
    baseline_scorecard = _j(root, BASELINE_SCORECARD)
    benchmark_receipt = _j(root, BENCHMARK_RECEIPT)
    alias_retirement = _j(root, ALIAS_RETIREMENT)
    detachment_receipt = _j(root, DETACHMENT_RECEIPT)
    e2_receipt = _j(root, E2_RECEIPT)
    return {
        "schema_id": "kt.final_current_head.claim_class_outcome.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if final_blockers.get("status") == "PASS"
        and str(wave5_tier.get("status", "")).strip() == "PASS"
        and str(product_install.get("status", "")).strip() == "PASS"
        and str(operator_handoff.get("status", "")).strip() == "PASS"
        and str(standards.get("status", "")).strip() == "PASS"
        and str(baseline_scorecard.get("status", "")).strip() == "PASS"
        and str(benchmark_receipt.get("status", "")).strip() == "PASS"
        and str(alias_retirement.get("status", "")).strip() == "PASS"
        and str(detachment_receipt.get("status", "")).strip() == "PASS"
        else "FAIL",
        "claim_boundary": "This outcome compiles current-head claim truth from live W0-W7 surfaces only. It does not import historical bounded packets into current-head standing.",
        "externality_class_max": str(truth_lock.get("claim_ceiling_enforcements", {}).get("externality_class_max", "")).strip(),
        "comparative_widening": str(truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "")).strip(),
        "commercial_widening": str(truth_lock.get("claim_ceiling_enforcements", {}).get("commercial_widening", "")).strip(),
        "current_head_claim_class": str(wave5_tier.get("tier_id", "")).strip(),
        "current_head_runtime_truth_class": "BOUNDED_CURRENT_HEAD_ORGANISM_E1",
        "current_head_product_truth_class": "BOUNDED_E1_BUYER_SIMPLE_PRODUCT_PLANE",
        "router_canonical_status": str(router_ordered.get("canonical_router_status", "")).strip(),
        "router_superiority_earned": bool(router_score.get("superiority_earned")),
        "learned_router_cutover_allowed": bool(router_ordered.get("learned_router_cutover_allowed")),
        "multi_lobe_promotion_allowed": bool(router_ordered.get("multi_lobe_promotion_allowed")),
        "e2_outcome": str(e2_receipt.get("e2_outcome", "")).strip(),
        "operator_install_profile_status": str(product_install.get("status", "")).strip(),
        "operator_handoff_status": str(operator_handoff.get("status", "")).strip(),
        "standards_legibility_status": str(standards.get("status", "")).strip(),
        "source_refs": [TRUTH_LOCK, W5_TIER, ROUTER_ORDERED, ROUTER_SCORE, PRODUCT_INSTALL, OPERATOR_HANDOFF, STANDARDS, BASELINE_SCORECARD, BENCHMARK_RECEIPT, ALIAS_RETIREMENT, DETACHMENT_RECEIPT, E2_RECEIPT, OUT_BLOCKERS],
    }


def build_final_forbidden_claims(*, root: Path, claims: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        "Do not claim E2, E3, or E4 while the current externality ceiling remains E1_SAME_HOST_DETACHED_REPLAY.",
        "Do not claim cross-host reproducibility or friendly cross-host replay.",
        "Do not claim hostile or outsider verification.",
        "Do not claim learned-router superiority or learned-router cutover.",
        "Do not claim multi-lobe orchestration readiness or promotion.",
        "Do not claim comparative or category-leading superiority.",
        "Do not claim enterprise readiness or broad commercial readiness.",
        "Do not claim frontier, SOTA, or beyond-SOTA standing.",
        "Do not use historical bounded proof to upgrade current-head runtime, product, or tier truth.",
    ]
    return {
        "schema_id": "kt.final_current_head.forbidden_claims_list.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS",
        "claim_boundary": "This list compiles the exact stronger claims that remain forbidden on current head after W8.",
        "externality_class_max": str(claims.get("externality_class_max", "")).strip(),
        "forbidden_claim_count": len(rows),
        "forbidden_claims_remaining": rows,
        "source_refs": [TRUTH_LOCK, ROUTER_ORDERED, ROUTER_SCORE, BASELINE_SCORECARD, ALIAS_RETIREMENT, DETACHMENT_RECEIPT, PRODUCT_INSTALL, C006_STATUS],
    }


def build_final_product_truth_boundary(*, root: Path, claims: Dict[str, Any]) -> Dict[str, Any]:
    deploy_source = _j(root, PROD_DEPLOY)
    deploy_report = _j(root, DEPLOY_REPORT)
    product_install = _j(root, PRODUCT_INSTALL)
    operator_handoff = _j(root, OPERATOR_HANDOFF)
    standards = _j(root, STANDARDS)
    support = _j(root, SUPPORT)
    wrapper = _j(root, WRAPPER)
    one_page = _txt(root, ONE_PAGE)
    runbook = _txt(root, RUNBOOK)
    checks = [
        {
            "check_id": "deployment_profiles_active_and_bounded",
            "pass": str(deploy_source.get("status", "")).strip() == "ACTIVE"
            and str(deploy_report.get("status", "")).strip() == "ACTIVE"
            and int(deploy_report.get("product_profile_count", 0) or 0) == 3,
            "ref": PROD_DEPLOY,
        },
        {
            "check_id": "buyer_simple_install_and_handoff_pass",
            "pass": str(product_install.get("status", "")).strip() == "PASS"
            and str(operator_handoff.get("status", "")).strip() == "PASS",
            "ref": PRODUCT_INSTALL,
        },
        {
            "check_id": "support_boundary_remains_bounded",
            "pass": support.get("no_training_default") is True and support.get("runtime_cutover_allowed") is False,
            "ref": SUPPORT,
        },
        {
            "check_id": "standards_legibility_is_informative_only",
            "pass": str(standards.get("status", "")).strip() == "PASS",
            "ref": STANDARDS,
        },
        {
            "check_id": "one_page_surfaces_restate_e1_boundary",
            "pass": _all(one_page + "\n" + runbook, ["E1", "Do not claim enterprise readiness", "Do not claim comparative"]),
            "ref": ONE_PAGE,
        },
    ]
    return {
        "schema_id": "kt.product.final_truth_boundary.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS" if all(bool(item["pass"]) for item in checks) else "FAIL",
        "claim_boundary": "The final product truth boundary is one buyer-simple bounded E1 verifier-backed product plane only. It does not widen externality, runtime, or enterprise truth.",
        "product_truth_class": str(claims.get("current_head_product_truth_class", "")).strip(),
        "max_externality_class": str(claims.get("externality_class_max", "")).strip(),
        "install_to_pass_fail_minutes": int(product_install.get("local_profile_install_to_pass_fail_minutes", 0) or 0),
        "product_profile_ids": [str(row.get("profile_id", "")).strip() for row in deploy_source.get("profiles", []) if isinstance(row, dict)],
        "supported_entrypoints": [str(row.get("command", "")).strip() for row in wrapper.get("entrypoints", []) if isinstance(row, dict)],
        "unsupported_claims": ["cross_host_proven", "independent_or_hostile_verification_proven", "enterprise_ready", "comparative_superiority"],
        "checks": checks,
        "source_refs": [PROD_DEPLOY, DEPLOY_REPORT, PRODUCT_INSTALL, OPERATOR_HANDOFF, STANDARDS, SUPPORT, WRAPPER, ONE_PAGE, RUNBOOK, NIST, ISO42001, EUAI, COMMERCIAL, VERIFIER, AUDIT_PACKET],
    }


def build_final_tier_ruling(*, root: Path, claims: Dict[str, Any], product_boundary: Dict[str, Any]) -> Dict[str, Any]:
    wave5_tier = _j(root, W5_TIER)
    frontier = (
        str(claims.get("externality_class_max", "")).strip() != "E1_SAME_HOST_DETACHED_REPLAY"
        and str(claims.get("comparative_widening", "")).strip() != "FORBIDDEN"
        and bool(claims.get("router_superiority_earned"))
    )
    category = frontier and str(claims.get("e2_outcome", "")).strip().startswith("E2")
    sota = category and str(claims.get("e2_outcome", "")).strip().startswith("E3")
    if sota:
        highest = "SOTA_CANDIDATE"
    elif category:
        highest = "CATEGORY_LEADING_CANDIDATE"
    elif frontier:
        highest = "FRONTIER_CANDIDATE"
    else:
        highest = "NOT_FRONTIER"
    return {
        "schema_id": "kt.final_current_head.tier_ruling.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS" if str(claims.get("status", "")).strip() == "PASS" and str(product_boundary.get("status", "")).strip() == "PASS" else "FAIL",
        "claim_boundary": "This ruling is compiled from current-head W0-W7 evidence only. It does not import historical bounded proof or prestige language that current head has not earned.",
        "current_head_tier_id": str(claims.get("current_head_claim_class", "")).strip() or str(wave5_tier.get("tier_id", "")).strip(),
        "highest_truthful_tier_output": highest,
        "tier_output_eligibility_checks": {
            "frontier_candidate": frontier,
            "category_leading_candidate": category,
            "sota_candidate": sota,
            "beyond_sota_candidate": False,
        },
        "reasons": [
            "Current externality remains bounded at E1 same-host detached replay.",
            "Comparative widening remains forbidden.",
            "Learned-router superiority is not earned and static routing remains canonical.",
            "Multi-lobe orchestration remains blocked.",
            "The product plane is buyer-simple but still bounded and non-enterprise.",
        ],
        "source_refs": [OUT_CLAIMS, OUT_PRODUCT, BASELINE_SCORECARD, BENCHMARK_RECEIPT, DETACHMENT_RECEIPT, E2_RECEIPT, W5_TIER],
    }


def build_receipt(*, root: Path, blockers: Dict[str, Any], claims: Dict[str, Any], forbidden: Dict[str, Any], product_boundary: Dict[str, Any], tier: Dict[str, Any]) -> Dict[str, Any]:
    truth_lock = _j(root, TRUTH_LOCK)
    firewall = _j(root, HIST_FIREWALL)
    wave5_readj = _j(root, W5_READJ)
    baseline_scorecard = _j(root, BASELINE_SCORECARD)
    benchmark_receipt = _j(root, BENCHMARK_RECEIPT)
    detachment_receipt = _j(root, DETACHMENT_RECEIPT)
    router_ordered = _j(root, ROUTER_ORDERED)
    commercial = _j(root, COMMERCIAL)
    verifier = _j(root, VERIFIER)
    e1 = _j(root, E1_RECEIPT)
    checks = [
        {"check_id": "live_current_head_sources_pass", "pass": all(str(obj.get("status", "")).strip() == "PASS" for obj in (truth_lock, wave5_readj, commercial, verifier, e1)), "ref": TRUTH_LOCK},
        {"check_id": "historical_uplift_firewall_active", "pass": str(truth_lock.get("historical_claim_firewall_status", "")).strip() == "ACTIVE" and str(firewall.get("status", "")).strip() == "ACTIVE", "ref": HIST_FIREWALL},
        {"check_id": "current_head_blocker_count_is_one", "pass": blockers.get("active_current_head_claim_blocker_ids", []) == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"], "ref": OUT_BLOCKERS},
        {"check_id": "comparative_and_product_widening_stay_blocked", "pass": str(claims.get("comparative_widening", "")).strip() == "FORBIDDEN" and str(claims.get("commercial_widening", "")).strip() == "FORBIDDEN", "ref": OUT_CLAIMS},
        {"check_id": "canonical_baseline_scorecard_still_passes", "pass": str(baseline_scorecard.get("status", "")).strip() == "PASS" and str(benchmark_receipt.get("status", "")).strip() == "PASS", "ref": BASELINE_SCORECARD},
        {"check_id": "competitive_alias_detachment_still_passes", "pass": str(detachment_receipt.get("status", "")).strip() == "PASS", "ref": DETACHMENT_RECEIPT},
        {"check_id": "router_and_lobe_promotions_remain_unearned", "pass": bool(claims.get("router_superiority_earned")) is False and bool(router_ordered.get("multi_lobe_promotion_allowed")) is False, "ref": ROUTER_ORDERED},
        {"check_id": "final_tier_output_is_compiled_without_prestige_inflation", "pass": str(tier.get("highest_truthful_tier_output", "")).strip() == "NOT_FRONTIER", "ref": OUT_TIER},
        {"check_id": "final_product_truth_boundary_stays_bounded", "pass": str(product_boundary.get("status", "")).strip() == "PASS" and str(product_boundary.get("max_externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY", "ref": OUT_PRODUCT},
    ]
    return {
        "schema_id": "kt.final_current_head.adjudication_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS" if all(bool(item["pass"]) for item in checks) else "FAIL",
        "claim_boundary": "This receipt is the final current-head adjudication compiled from live W0-W7 evidence only. It does not use historical uplift or documentary substitution to widen current-head truth.",
        "compiled_from_refs": [TRUTH_LOCK, HIST_FIREWALL, W5_BLOCKERS, W5_TIER, W5_READJ, C006_STATUS, HEARTBEAT, COMMERCIAL, VERIFIER, C006_KIT, PRODUCT_INSTALL, OPERATOR_HANDOFF, STANDARDS, ROUTER_ORDERED, ROUTER_SCORE, BASELINE_SCORECARD, BENCHMARK_RECEIPT, ALIAS_RETIREMENT, DETACHMENT_RECEIPT, E2_RECEIPT, AUDIT_PACKET, E1_RECEIPT],
        "final_blocker_matrix_ref": OUT_BLOCKERS,
        "final_claim_class_outcome_ref": OUT_CLAIMS,
        "final_forbidden_claims_list_ref": OUT_FORBIDDEN,
        "final_product_truth_boundary_ref": OUT_PRODUCT,
        "final_tier_ruling_ref": OUT_TIER,
        "forbidden_claim_count": int(forbidden.get("forbidden_claim_count", 0) or 0),
        "exact_current_head_standing": {
            "open_current_head_claim_blocker_ids": list(blockers.get("active_current_head_claim_blocker_ids", [])),
            "current_head_claim_class": str(claims.get("current_head_claim_class", "")).strip(),
            "externality_class_max": str(claims.get("externality_class_max", "")).strip(),
            "highest_truthful_tier_output": str(tier.get("highest_truthful_tier_output", "")).strip(),
            "router_status": str(claims.get("router_canonical_status", "")).strip(),
            "product_truth_class": str(product_boundary.get("product_truth_class", "")).strip(),
        },
        "checks": checks,
        "next_lawful_move": "Continue bounded E1 delivery, operator flow, and buyer-safe packaging. Execute W6B immediately if second-host hardware appears.",
    }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Compile the final current-head adjudication from live W0-W7 evidence only.")
    p.add_argument("--allow-tracked-output-refresh", action="store_true")
    p.add_argument("--final-blocker-matrix-output", default=OUT_BLOCKERS)
    p.add_argument("--final-claim-class-output", default=OUT_CLAIMS)
    p.add_argument("--final-forbidden-claims-output", default=OUT_FORBIDDEN)
    p.add_argument("--final-product-truth-output", default=OUT_PRODUCT)
    p.add_argument("--final-tier-ruling-output", default=OUT_TIER)
    p.add_argument("--receipt-output", default=OUT_RECEIPT)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    root = repo_root()
    prewrite_dirty = _enforce_write_scope_pre(root)
    blockers = build_final_blocker_matrix(root=root)
    claims = build_final_claim_class_outcome(root=root, final_blockers=blockers)
    forbidden = build_final_forbidden_claims(root=root, claims=claims)
    product_boundary = build_final_product_truth_boundary(root=root, claims=claims)
    tier = build_final_tier_ruling(root=root, claims=claims, product_boundary=product_boundary)
    receipt = build_receipt(root=root, blockers=blockers, claims=claims, forbidden=forbidden, product_boundary=product_boundary, tier=tier)

    allowed_repo_writes: list[str] = []
    for target, payload, default_rel in [
        (_resolve(root, str(args.final_blocker_matrix_output)), blockers, OUT_BLOCKERS),
        (_resolve(root, str(args.final_claim_class_output)), claims, OUT_CLAIMS),
        (_resolve(root, str(args.final_forbidden_claims_output)), forbidden, OUT_FORBIDDEN),
        (_resolve(root, str(args.final_product_truth_output)), product_boundary, OUT_PRODUCT),
        (_resolve(root, str(args.final_tier_ruling_output)), tier, OUT_TIER),
        (_resolve(root, str(args.receipt_output)), receipt, OUT_RECEIPT),
    ]:
        written = _maybe_write_json_output(
            root=root,
            target=target,
            payload=payload,
            default_rel=default_rel,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    _enforce_write_scope_post(root, prewrite_dirty=prewrite_dirty, allowed_repo_writes=allowed_repo_writes)

    summary = {
        "status": receipt["status"],
        "open_current_head_claim_blocker_ids": blockers["active_current_head_claim_blocker_ids"],
        "highest_truthful_tier_output": tier["highest_truthful_tier_output"],
        "product_truth_class": product_boundary["product_truth_class"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
