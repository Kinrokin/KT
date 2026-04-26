from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-admissible-learned-router-candidate-source"
OUTCOME = "B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE_PACKET_BOUND"
REQUIRED_PREVIOUS_MOVE = "AUTHOR_B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE_PACKET"
NEXT_MOVE_IF_BLOCKED = "AUTHOR_B04_R6_FRESH_LEARNED_ROUTER_CANDIDATE_GENERATION_PACKET"
NEXT_MOVE_IF_AUTHORIZED = "EXECUTE_B04_R6_CANDIDATE_ADMISSIBILITY_SCREEN"

AUTHORIZED_OUTCOME = "R6_CANDIDATE_SOURCE_AUTHORIZED__ADMISSIBILITY_SCREEN_NEXT"
MISSING_PROVENANCE_OUTCOME = "R6_CANDIDATE_SOURCE_DEFERRED__MISSING_PROVENANCE"
NO_CANDIDATE_OUTCOME = "R6_CANDIDATE_SOURCE_BLOCKED__NO_ADMISSIBLE_CANDIDATE"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
    "external_verification_completed",
]

OUTPUTS = {
    "source_packet": "b04_r6_admissible_learned_router_candidate_source_packet.json",
    "receipt": "b04_r6_candidate_source_receipt.json",
    "rules": "b04_r6_candidate_source_rules_contract.json",
    "requirements": "b04_r6_candidate_admissibility_requirements.json",
    "disqualifiers": "b04_r6_candidate_source_disqualifier_contract.json",
    "inventory": "b04_r6_candidate_source_inventory.json",
    "provenance_matrix": "b04_r6_candidate_provenance_matrix.json",
    "trace_compatibility": "b04_r6_candidate_trace_compatibility_receipt.json",
    "contamination_scan": "b04_r6_candidate_beta_quarantine_contamination_scan_receipt.json",
    "validation_matrix": "b04_r6_candidate_source_validation_matrix.json",
    "blocker_ledger": "b04_r6_candidate_source_blocker_ledger.json",
    "next_court": "b04_r6_candidate_source_next_court_receipt.json",
    "fresh_generation_contract": "b04_r6_fresh_candidate_generation_lane_contract.json",
    "clean_state": "b04_r6_candidate_source_clean_state_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _sha_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved),
    }


def _base(*, generated_utc: str, head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "authoritative_lane": "B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE",
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "screen_execution_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)
    if payload.get("r6_authorized") is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep R6 unauthorized")
    if payload.get("learned_router_superiority_earned") is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must not claim learned-router superiority")
    if payload.get("learned_router_cutover_authorized") is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must not authorize learned-router cutover")


def _candidate_from_manifest(candidate_manifest: Dict[str, Any]) -> Dict[str, Any]:
    candidate = candidate_manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise RuntimeError("FAIL_CLOSED: learned-router candidate manifest must include candidate object")
    return candidate


def _ensure_inputs(
    *,
    candidate_input_receipt: Dict[str, Any],
    candidate_manifest: Dict[str, Any],
    input_manifest: Dict[str, Any],
    execution_mode: Dict[str, Any],
    scorecard: Dict[str, Any],
    router_policy: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> None:
    _ensure_boundaries(candidate_input_receipt, label="R6 candidate/input receipt")
    _ensure_boundaries(candidate_manifest, label="R6 learned-router candidate manifest")
    _ensure_boundaries(input_manifest, label="R6 bound input manifest")
    _ensure_boundaries(execution_mode, label="R6 shadow execution mode contract")
    common.ensure_pass(scorecard, label="router superiority scorecard")
    common.ensure_pass(live_validation, label="trust-zone validation")
    if candidate_input_receipt.get("next_lawful_move") != REQUIRED_PREVIOUS_MOVE:
        raise RuntimeError("FAIL_CLOSED: candidate/input receipt does not authorize candidate-source packet")
    if candidate_input_receipt.get("candidate_admissible") is not False:
        raise RuntimeError("FAIL_CLOSED: candidate/input receipt must keep candidate non-admissible before this court")
    if candidate_input_receipt.get("input_manifest_ready") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate/input receipt must have a ready input manifest")
    if candidate_input_receipt.get("screen_execution_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: candidate/input receipt must not authorize screen execution")
    if input_manifest.get("input_manifest_ready") is not True or not input_manifest.get("input_cases"):
        raise RuntimeError("FAIL_CLOSED: bound input manifest must preserve ready input cases")
    if execution_mode.get("activation_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must forbid activation")
    if execution_mode.get("package_promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must forbid package promotion")
    if execution_mode.get("lobe_promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must forbid lobe promotion")
    if execution_mode.get("product_or_commercial_claim_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must forbid product/commercial claims")
    candidate = _candidate_from_manifest(candidate_manifest)
    if candidate.get("admissible_for_shadow_screen") is not False:
        raise RuntimeError("FAIL_CLOSED: existing candidate manifest must not already be admissible")
    if candidate.get("promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: existing candidate must remain non-promotable")
    scorecard_candidate = scorecard.get("learned_router_candidate")
    if not isinstance(scorecard_candidate, dict):
        raise RuntimeError("FAIL_CLOSED: scorecard must include learned-router candidate object")
    if scorecard_candidate.get("promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: scorecard candidate must remain non-promotable")
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: scorecard must not claim superiority")
    policy = router_policy.get("learned_router_candidate_policy")
    if not isinstance(policy, dict):
        raise RuntimeError("FAIL_CLOSED: router policy registry must include learned-router candidate policy")
    if str(policy.get("current_status", "")).strip() != "BLOCKED_PENDING_ELIGIBLE_CANDIDATE_AND_CLEAN_WIN":
        raise RuntimeError("FAIL_CLOSED: router policy must keep learned-router candidate blocked pending clean win")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")


def _source_rules() -> Dict[str, Any]:
    return {
        "allowed_source_paths": [
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**/learned_router*.py",
            "KT_PROD_CLEANROOM/governance/*learned_router*candidate*.json",
            "KT_PROD_CLEANROOM/reports/*learned_router*candidate*.json",
            "KT_PROD_CLEANROOM/runs/**/learned_router_candidate_manifest.json",
        ],
        "allowed_source_zones": ["CANONICAL", "LAB", "GENERATED_RUNTIME_TRUTH"],
        "zone_rules": {
            "CANONICAL": "Allowed only if source, provenance, training/eval, and trace compatibility are hash-bound.",
            "LAB": "Allowed only as shadow-only input after explicit lab-to-court adoption receipt; never live authority.",
            "GENERATED_RUNTIME_TRUTH": "Allowed only when generated from tracked law and immutable source hashes.",
            "ARCHIVE": "Not admissible as source authority; may be cited only as historical lineage.",
            "COMMERCIAL": "Not admissible as proof source.",
            "QUARANTINED": "Not admissible.",
        },
        "fresh_generation_allowed": True,
        "existing_artifact_promotion_allowed": True,
        "promotion_condition": "Existing artifacts may enter only through a candidate-source receipt with provenance, hash, zone, and trace compatibility.",
    }


def _requirements(input_manifest: Dict[str, Any]) -> list[Dict[str, Any]]:
    case_ids = [str(row.get("case_id", "")).strip() for row in input_manifest.get("input_cases", []) if isinstance(row, dict)]
    return [
        {"id": "CANDIDATE_ID_BOUND", "rule": "candidate_id must be non-empty and stable"},
        {"id": "SOURCE_PATH_BOUND", "rule": "candidate_source_ref must point to a tracked source artifact"},
        {"id": "SOURCE_HASH_BOUND", "rule": "candidate source and manifest must carry SHA256 hashes"},
        {"id": "PROVENANCE_CHAIN_BOUND", "rule": "candidate must have a derivation or training lineage receipt"},
        {"id": "TRAINING_EVAL_RECEIPT_BOUND", "rule": "candidate must have training/eval receipt before admissibility screen"},
        {"id": "NO_BETA_CONTAMINATION", "rule": "candidate may not depend on beta or holdout-contaminated material"},
        {"id": "NO_PACKAGE_PROMOTION_DEPENDENCY", "rule": "candidate may not require deferred package promotion"},
        {"id": "SHADOW_ONLY_RUNNABLE", "rule": "candidate must run in shadow-only mode with activation disabled"},
        {"id": "INPUT_UNIVERSE_COMPATIBLE", "rule": f"candidate must support frozen cases {case_ids} without case mutation"},
        {"id": "TRACE_SCHEMA_COMPATIBLE", "rule": "candidate must emit route, abstention, over-routing, and mirror/masked traces"},
        {"id": "DETERMINISTIC_REPLAYABLE", "rule": "candidate must be deterministic or seed-bound and replayable"},
        {"id": "TRUST_ZONE_COMPATIBLE", "rule": "candidate source zone must not violate canonical/trust-zone boundaries"},
    ]


def _disqualifiers() -> list[Dict[str, str]]:
    return [
        {"id": "MISSING_CANDIDATE_ID", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "MISSING_SOURCE_HASH", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "MISSING_PROVENANCE", "effect": "DEFER_CANDIDATE_SOURCE"},
        {"id": "WRONG_ZONE", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "STALE_ARTIFACT", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "BETA_CONTAMINATION", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "UNABLE_TO_EMIT_ROUTE_TRACES", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "NONDETERMINISTIC_OR_UNREPLAYABLE", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "PACKAGE_PROMOTION_DEPENDENCY", "effect": "BLOCK_CANDIDATE_SOURCE"},
        {"id": "TRUST_ZONE_BOUNDARY_VIOLATION", "effect": "HALT_AND_BLOCK"},
    ]


def _candidate_inventory(candidate_manifest: Dict[str, Any], scorecard: Dict[str, Any], router_policy: Dict[str, Any]) -> list[Dict[str, Any]]:
    manifest_candidate = dict(candidate_manifest.get("candidate", {}))
    scorecard_candidate = dict(scorecard.get("learned_router_candidate", {}))
    return [
        {
            "inventory_id": "current_candidate_manifest_slot",
            "source_ref": "KT_PROD_CLEANROOM/reports/b04_r6_learned_router_candidate_manifest.json",
            "candidate_id": manifest_candidate.get("candidate_id", ""),
            "candidate_status": manifest_candidate.get("candidate_status", ""),
            "candidate_source_ref": manifest_candidate.get("candidate_source_ref"),
            "zone": manifest_candidate.get("zone", ""),
            "admissible": False,
            "reason": manifest_candidate.get("admissibility_reason", "No admissible candidate bound."),
        },
        {
            "inventory_id": "router_superiority_scorecard_candidate",
            "source_ref": "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json",
            "candidate_id": scorecard_candidate.get("candidate_id", ""),
            "candidate_status": scorecard_candidate.get("candidate_status", ""),
            "candidate_source_ref": None,
            "zone": "INTENDED_NOT_PROMOTED",
            "admissible": False,
            "reason": scorecard_candidate.get("eligibility_reason", "Scorecard does not bind an eligible candidate."),
        },
        {
            "inventory_id": "router_policy_candidate_rule",
            "source_ref": "KT_PROD_CLEANROOM/governance/router_policy_registry.json",
            "candidate_id": "",
            "candidate_status": dict(router_policy.get("learned_router_candidate_policy", {})).get("current_status", ""),
            "candidate_source_ref": None,
            "zone": "POLICY_ONLY",
            "admissible": False,
            "reason": "Policy rule is not a candidate artifact.",
        },
    ]


def _evidence_refs(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    rels = {
        "candidate_input_receipt": reports_root / "b04_r6_shadow_router_candidate_input_manifest_receipt.json",
        "candidate_manifest": reports_root / "b04_r6_learned_router_candidate_manifest.json",
        "bound_input_manifest": reports_root / "b04_r6_shadow_router_input_manifest_bound.json",
        "execution_mode_contract": reports_root / "b04_r6_shadow_router_execution_mode_contract.json",
        "router_superiority_scorecard": reports_root / "router_superiority_scorecard.json",
        "router_policy_registry": governance_root / "router_policy_registry.json",
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
    }
    return {key: _sha_ref(path, root=root) for key, path in rels.items()}


def _build_payloads(
    *,
    generated_utc: str,
    head: str,
    evidence_refs: Dict[str, Dict[str, str]],
    candidate_manifest: Dict[str, Any],
    input_manifest: Dict[str, Any],
    scorecard: Dict[str, Any],
    router_policy: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    base = _base(generated_utc=generated_utc, head=head)
    source_rules = _source_rules()
    requirements = _requirements(input_manifest)
    disqualifiers = _disqualifiers()
    inventory = _candidate_inventory(candidate_manifest, scorecard, router_policy)
    admissible = [row for row in inventory if row.get("admissible") is True]
    verdict = AUTHORIZED_OUTCOME if admissible else NO_CANDIDATE_OUTCOME
    next_lawful_move = NEXT_MOVE_IF_AUTHORIZED if admissible else NEXT_MOVE_IF_BLOCKED
    source_packet = {
        "schema_id": "kt.operator.b04_r6_admissible_learned_router_candidate_source_packet.v1",
        **base,
        "outcome": OUTCOME,
        "verdict": verdict,
        "candidate_source_authorized": bool(admissible),
        "admissible_candidate_count": len(admissible),
        "candidate_inventory_count": len(inventory),
        "source_rules_ref": OUTPUTS["rules"],
        "admissibility_requirements_ref": OUTPUTS["requirements"],
        "disqualifier_contract_ref": OUTPUTS["disqualifiers"],
        "allowed_outcomes": [AUTHORIZED_OUTCOME, MISSING_PROVENANCE_OUTCOME, NO_CANDIDATE_OUTCOME],
        "non_claim_boundary": [
            "does not authorize R6",
            "does not execute the shadow screen",
            "does not prove learned-router superiority",
            "does not activate learned routing",
            "does not open lobe escalation",
        ],
        "evidence_refs": evidence_refs,
        "next_lawful_move": next_lawful_move,
    }
    receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_source_receipt.v1",
        **base,
        "outcome": OUTCOME,
        "verdict": verdict,
        "candidate_source_authorized": bool(admissible),
        "admissible_candidate_count": len(admissible),
        "screen_execution_authorized": False,
        "next_lawful_move": next_lawful_move,
    }
    validation_matrix = {
        "schema_id": "kt.operator.b04_r6_candidate_source_validation_matrix.v1",
        **base,
        "checks": [
            {"check": "previous_candidate_input_receipt_pass", "status": "PASS"},
            {"check": "input_manifest_ready", "status": "PASS"},
            {"check": "candidate_source_rules_bound", "status": "PASS"},
            {"check": "admissibility_requirements_bound", "status": "PASS"},
            {"check": "disqualifiers_bound", "status": "PASS"},
            {"check": "candidate_inventory_completed", "status": "PASS"},
            {"check": "admissible_candidate_present", "status": "PASS" if admissible else "BLOCKED"},
            {"check": "screen_execution_not_authorized", "status": "PASS"},
        ],
        "failures": [] if admissible else [{"check": "admissible_candidate_present", "reason": "No admissible learned-router candidate source is bound."}],
        "next_lawful_move": next_lawful_move,
    }
    blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_candidate_source_blocker_ledger.v1",
        **base,
        "live_blocker_count": 0 if admissible else 1,
        "r6_blocker_count": 0 if admissible else 1,
        "entries": []
        if admissible
        else [
            {
                "blocker_id": "B04_R6_NO_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE",
                "status": "ACTIVE_BLOCKER",
                "resolution_path": NEXT_MOVE_IF_BLOCKED,
            }
        ],
        "next_lawful_move": next_lawful_move,
    }
    prep_common = _base(generated_utc=generated_utc, head=head, status="PREP_ONLY")
    return {
        OUTPUTS["source_packet"]: source_packet,
        OUTPUTS["receipt"]: receipt,
        OUTPUTS["rules"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_rules_contract.v1",
            **base,
            **source_rules,
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["requirements"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_requirements.v1",
            **base,
            "requirements": requirements,
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["disqualifiers"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_disqualifier_contract.v1",
            **base,
            "disqualifiers": disqualifiers,
            "effect_rule": "Any block disqualifier prevents candidate-source authorization; HALT_AND_BLOCK stops the lane.",
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["inventory"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_inventory.v1",
            **base,
            "candidate_inventory": inventory,
            "admissible_candidate_count": len(admissible),
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["provenance_matrix"]: {
            "schema_id": "kt.operator.b04_r6_candidate_provenance_matrix.v1",
            **base,
            "rows": [
                {
                    "inventory_id": row["inventory_id"],
                    "candidate_id_bound": bool(str(row.get("candidate_id", "")).strip()),
                    "source_ref_bound": bool(row.get("candidate_source_ref")),
                    "source_hash_bound": False,
                    "training_lineage_bound": False,
                    "admissible": row["admissible"],
                }
                for row in inventory
            ],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["trace_compatibility"]: {
            "schema_id": "kt.operator.b04_r6_candidate_trace_compatibility_receipt.v1",
            **prep_common,
            "trace_schema_refs": [
                "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_route_decision_trace_schema.json",
                "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_abstention_overrouting_trace_schema.json",
                "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_mirror_masked_invariance_trace_schema.json",
            ],
            "candidate_trace_compatible": False,
            "why": "No candidate source is bound to test against trace schemas.",
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["contamination_scan"]: {
            "schema_id": "kt.operator.b04_r6_candidate_beta_quarantine_contamination_scan_receipt.v1",
            **prep_common,
            "scan_scope": "candidate inventory rows only",
            "beta_contamination_detected": False,
            "quarantined_source_detected": False,
            "candidate_present": bool(admissible),
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["validation_matrix"]: validation_matrix,
        OUTPUTS["blocker_ledger"]: blocker_ledger,
        OUTPUTS["next_court"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_next_court_receipt.v1",
            **base,
            "verdict": verdict,
            "candidate_source_authorized": bool(admissible),
            "allowed_outcomes": [AUTHORIZED_OUTCOME, MISSING_PROVENANCE_OUTCOME, NO_CANDIDATE_OUTCOME],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["fresh_generation_contract"]: {
            "schema_id": "kt.operator.b04_r6_fresh_candidate_generation_lane_contract.v1",
            **prep_common,
            "fresh_generation_lane_needed": not bool(admissible),
            "generation_lane_must_bind": [
                "candidate_id",
                "source path",
                "source hash",
                "training or derivation receipt",
                "eval receipt",
                "shadow-only execution harness",
                "trace compatibility",
                "beta/holdout exclusion receipt",
            ],
            "generation_lane_forbidden": FORBIDDEN_CLAIMS,
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["clean_state"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_clean_state_receipt.v1",
            **base,
            "current_git_branch": REQUIRED_BRANCH,
            "worktree_clean_at_lane_start": True,
            "next_lawful_move": next_lawful_move,
        },
    }


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 candidate-source run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")

    candidate_input_receipt = _load(
        root,
        "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_candidate_input_manifest_receipt.json",
        label="R6 candidate/input receipt",
    )
    candidate_manifest = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_learned_router_candidate_manifest.json", label="R6 candidate manifest")
    input_manifest = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_input_manifest_bound.json", label="R6 bound input manifest")
    execution_mode = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_execution_mode_contract.json", label="R6 execution mode")
    scorecard = _load(root, "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json", label="router superiority scorecard")
    router_policy = _load(root, "KT_PROD_CLEANROOM/governance/router_policy_registry.json", label="router policy registry")
    live_validation = validate_trust_zones(root=root)
    _ensure_inputs(
        candidate_input_receipt=candidate_input_receipt,
        candidate_manifest=candidate_manifest,
        input_manifest=input_manifest,
        execution_mode=execution_mode,
        scorecard=scorecard,
        router_policy=router_policy,
        live_validation=live_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    evidence_refs = _evidence_refs(root, reports_root.resolve(), governance_root.resolve())
    payloads = _build_payloads(
        generated_utc=generated_utc,
        head=head,
        evidence_refs=evidence_refs,
        candidate_manifest=candidate_manifest,
        input_manifest=input_manifest,
        scorecard=scorecard,
        router_policy=router_policy,
    )
    for filename, payload in payloads.items():
        write_json_stable((reports_root / filename).resolve(), payload)
    receipt = payloads[OUTPUTS["receipt"]]
    return {
        "outcome": OUTCOME,
        "verdict": receipt["verdict"],
        "candidate_source_authorized": receipt["candidate_source_authorized"],
        "next_lawful_move": receipt["next_lawful_move"],
        "output_count": len(payloads),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind B04 R6 admissible learned-router candidate source packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
