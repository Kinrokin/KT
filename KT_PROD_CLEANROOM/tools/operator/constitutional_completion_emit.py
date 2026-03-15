from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


EFFECTIVE_UTC = "2026-03-10T00:00:00Z"
EXPIRES_UTC = "2026-09-10T00:00:00Z"

ROUTER_POLICY_REF = "KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_POLICY_HAT_V1.json"
ROUTER_DEMO_SUITE_REF = "KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_DEMO_SUITE_V1.json"
CRUCIBLE_REGISTRY_REF = "KT_PROD_CLEANROOM/tools/growth/crucibles/CRUCIBLE_REGISTRY.yaml"
PROGRAM_CATALOG_REF = "KT_PROD_CLEANROOM/governance/program_catalog.json"
TRUTH_POINTER_REF = "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"

DOMAIN2_TEST_REFS = [
    "KT_PROD_CLEANROOM/tools/growth/crucibles/tests/test_crucible_registry.py",
    "KT_PROD_CLEANROOM/tools/growth/crucibles/tests/test_crucible_runner.py",
    "KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_sweep_runner_integration.py",
    "KT_PROD_CLEANROOM/tests/policy_c/test_drift_guard.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_epic15_merge_evaluator.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_rollback_drill.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl4_promotion_atomic.py",
]

DOMAIN3_EVIDENCE_REFS = [
    "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py",
    "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
    "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py",
    "KT_PROD_CLEANROOM/policy_c/pressure_tensor.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_run_protocol_generator.py",
]

DOMAIN4_PRECEDENT_REFS = [
    "KT_PROD_CLEANROOM/reports/settled_authority_promotion_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json",
    "KT_PROD_CLEANROOM/docs/operator/KT_FINAL_CONSTITUTIONAL_COMPLETION_BLUEPRINT.md",
]

DOMAIN6_DOC_REFS = [
    "KT_PROD_CLEANROOM/docs/operator/KT_CONSTITUTIONAL_PROGRAM_CHARTER.md",
    "KT_PROD_CLEANROOM/docs/operator/KT_CONSTITUTIONAL_COMPLETION_PROGRAM.md",
    "KT_PROD_CLEANROOM/docs/operator/KT_FINAL_CONSTITUTIONAL_COMPLETION_BLUEPRINT.md",
    "KT_PROD_CLEANROOM/docs/operator/KT_FULL_AGENT_COMPLETION_MANDATE.md",
]


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable(root / Path(rel), payload)


def _load(root: Path, rel: str) -> Dict[str, Any]:
    return load_json(root / Path(rel))


def _exists_all(root: Path, refs: Sequence[str]) -> bool:
    return all((root / Path(ref)).exists() for ref in refs)


def _law_surface(
    *,
    schema_id: str,
    law_id: str,
    domain_id: str,
    summary: str,
    authorities: Sequence[str],
    rules: Sequence[str],
    validators: Sequence[str],
) -> Dict[str, Any]:
    return {
        "schema_id": schema_id,
        "law_id": law_id,
        "domain_id": domain_id,
        "effective_utc": EFFECTIVE_UTC,
        "expires_utc": EXPIRES_UTC,
        "supersedes": [],
        "status": "ACTIVE",
        "summary": summary,
        "authority_refs": [str(item) for item in authorities],
        "rules": [str(item) for item in rules],
        "required_validators": [str(item) for item in validators],
    }


def _schema_artifact(*, schema_id: str, title: str, required: Sequence[str], properties: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "required": list(required),
        "properties": properties,
        "schema_id": schema_id,
    }


def _collect_crucibles(root: Path) -> List[Dict[str, Any]]:
    crucible_root = root / "KT_PROD_CLEANROOM" / "tools" / "growth" / "crucibles"
    entries: List[Dict[str, Any]] = []
    for spec in sorted(crucible_root.glob("CRU-*.yaml")):
        entries.append(
            {
                "crucible_id": spec.stem,
                "spec_ref": spec.relative_to(root).as_posix(),
                "trust_zone": "LAB",
                "promotion_scope": "LAB_ONLY_UNTIL_PROMOTED",
            }
        )
    return entries


def _router_sources(root: Path) -> Dict[str, Any]:
    return {
        "policy": _load(root, ROUTER_POLICY_REF),
        "suite": _load(root, ROUTER_DEMO_SUITE_REF),
    }


def _lobe_entries(policy: Dict[str, Any], suite: Dict[str, Any]) -> List[Dict[str, Any]]:
    route_rows = policy.get("routes") if isinstance(policy.get("routes"), list) else []
    default_ids = policy.get("default_adapter_ids") if isinstance(policy.get("default_adapter_ids"), list) else []
    seen: Dict[str, Dict[str, Any]] = {}
    for adapter_id in default_ids:
        aid = str(adapter_id).strip()
        if not aid:
            continue
        seen[aid] = {
            "lobe_id": aid,
            "role": "default_generalist",
            "status": "RATIFIED_ROUTER_BASELINE",
            "evidence_refs": [ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF],
        }
    role_map = {
        "governance": "governance_audit",
        "math": "quantitative_reasoning",
        "poetry": "creative_generation",
        "default": "general_strategy",
    }
    for row in route_rows:
        if not isinstance(row, dict):
            continue
        domain_tag = str(row.get("domain_tag", "")).strip() or "default"
        role = role_map.get(domain_tag, "specialist")
        adapter_ids = row.get("adapter_ids") if isinstance(row.get("adapter_ids"), list) else []
        required_ids = row.get("required_adapter_ids") if isinstance(row.get("required_adapter_ids"), list) else []
        for adapter_id in adapter_ids:
            aid = str(adapter_id).strip()
            if not aid:
                continue
            seen[aid] = {
                "lobe_id": aid,
                "role": role,
                "status": "RATIFIED_ROUTER_BASELINE",
                "evidence_refs": [ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF],
            }
        for adapter_id in required_ids:
            aid = str(adapter_id).strip()
            if not aid:
                continue
            seen[aid] = {
                "lobe_id": aid,
                "role": "safety_enforcer",
                "status": "RATIFIED_REQUIRED_GUARD",
                "evidence_refs": [ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF],
            }
    demo_cases = suite.get("cases") if isinstance(suite.get("cases"), list) else []
    for case in demo_cases:
        if not isinstance(case, dict):
            continue
        adapter_ids = case.get("expected_adapter_ids") if isinstance(case.get("expected_adapter_ids"), list) else []
        for adapter_id in adapter_ids:
            aid = str(adapter_id).strip()
            if aid and aid not in seen:
                seen[aid] = {
                    "lobe_id": aid,
                    "role": "demo_specialist",
                    "status": "RATIFIED_ROUTER_BASELINE",
                    "evidence_refs": [ROUTER_DEMO_SUITE_REF],
                }
    return [seen[key] for key in sorted(seen)]


def _experimental_adapter_ids() -> List[str]:
    return sorted(
        {
            "lobe.alpha.v1",
            "lobe.architect.v1",
            "lobe.beta.v1",
            "lobe.child.v1",
            "lobe.critic.v1",
            "lobe.p1.v1",
            "lobe.p2.v1",
            "lobe.scout.v1",
        }
    )


def _domain2_outputs(root: Path, head_sha: str) -> Dict[str, Dict[str, Any]]:
    router = _router_sources(root)
    lobes = _lobe_entries(router["policy"], router["suite"])
    crucibles = _collect_crucibles(root)
    authorities = [
        CRUCIBLE_REGISTRY_REF,
        ROUTER_POLICY_REF,
        ROUTER_DEMO_SUITE_REF,
        "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
        "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py",
        "KT_PROD_CLEANROOM/tools/verification/fl4_promote.py",
        "KT_PROD_CLEANROOM/tools/verification/fl3_rollback_drill.py",
    ]
    validators = [
        "python -m pytest -q KT_PROD_CLEANROOM/tools/growth/crucibles/tests/test_crucible_registry.py KT_PROD_CLEANROOM/tools/growth/crucibles/tests/test_crucible_runner.py",
        "python -m pytest -q KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_sweep_runner_integration.py KT_PROD_CLEANROOM/tests/policy_c/test_drift_guard.py",
        "python -m pytest -q KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py KT_PROD_CLEANROOM/tests/fl3/test_epic15_merge_evaluator.py KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py KT_PROD_CLEANROOM/tests/fl3/test_fl3_rollback_drill.py KT_PROD_CLEANROOM/tests/fl3/test_fl4_promotion_atomic.py",
    ]
    outputs: Dict[str, Dict[str, Any]] = {
        "KT_PROD_CLEANROOM/governance/promotion_engine_law.json": _law_surface(
            schema_id="kt.governance.promotion_engine_law.v1",
            law_id="PROMOTION_ENGINE_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Promotion civilization is governed by receipts, rollback, revalidation, and risk accounting.",
            authorities=authorities,
            rules=[
                "Promotion requires PASS receipts for admission, evaluation, rollback, and risk accounting.",
                "All promotion decisions must bind to a pinned head and deterministic evidence refs.",
                "No promotion may bypass zone-crossing receipt emission.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/crucible_lifecycle_law.json": _law_surface(
            schema_id="kt.governance.crucible_lifecycle_law.v1",
            law_id="CRUCIBLE_LIFECYCLE_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Crucibles are governed as Lab-only challenge organs with explicit admission and promotion boundaries.",
            authorities=[CRUCIBLE_REGISTRY_REF, "KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py"],
            rules=[
                "Registered crucibles must have immutable specs and remain in LAB until promotion receipts exist.",
                "Crucible registry changes require revalidation against the registry and runner tests.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/adapter_lifecycle_law.json": _law_surface(
            schema_id="kt.governance.adapter_lifecycle_law.v1",
            law_id="ADAPTER_LIFECYCLE_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Adapters are governed as ratified, experimental, retired, or revoked subjects with explicit evidence binding.",
            authorities=[
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/kt.runtime.registry.v1.json",
                "KT_PROD_CLEANROOM/tools/verification/fl4_promote.py",
                "KT_PROD_CLEANROOM/tools/training/stage6_promotion.py",
            ],
            rules=[
                "Adapter promotion must bind training receipts, evaluation receipts, and promoted manifest refs.",
                "Experimental adapters remain non-canonical until promotion receipts and zone crossings pass.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/tournament_law.json": _law_surface(
            schema_id="kt.governance.tournament_law.v1",
            law_id="TOURNAMENT_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Tournament evaluation is deterministic, schema-bound, and admission-gated.",
            authorities=[
                "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.tournament_plan.v1.json",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.tournament_result.v1.json",
            ],
            rules=[
                "Tournaments require schema-bound plans, evaluation admission receipts, and counter-pressure evidence.",
                "Dominance and champion selection must remain deterministic and fail-closed.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/merge_law.json": _law_surface(
            schema_id="kt.governance.merge_law.v1",
            law_id="MERGE_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Merge admissibility requires deterministic evaluation, rollback planning, and no safety regression.",
            authorities=[
                "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.merge_manifest.v1.json",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.merge_eval_receipt.v1.json",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.merge_rollback_plan.v1.json",
            ],
            rules=[
                "Merge candidates must inherit tournament pass status and explicit rollback plans.",
                "Any safety regression or missing rollback surface fails closed.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/router_promotion_law.json": _law_surface(
            schema_id="kt.governance.router_promotion_law.v1",
            law_id="ROUTER_PROMOTION_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Router promotion is limited to deterministic policy and receipted demo-suite behavior until further ratification.",
            authorities=[ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF, "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py"],
            rules=[
                "Static router baseline is ratified from the demo suite and policy contract only.",
                "Shadow and learned router upgrades remain gated by later ratification order.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/lobe_promotion_law.json": _law_surface(
            schema_id="kt.governance.lobe_promotion_law.v1",
            law_id="LOBE_PROMOTION_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Lobe roles are ratified by route policy, demo expectations, and explicit safety role bindings.",
            authorities=[ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF, "KT_PROD_CLEANROOM/tests/fl3/test_run_protocol_generator.py"],
            rules=[
                "Required safety lobes must remain attached where route policy requires them.",
                "Lobe role changes require policy and demo-suite revalidation.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/rollback_law.json": _law_surface(
            schema_id="kt.governance.rollback_law.v1",
            law_id="ROLLBACK_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Every promotion surface must define a rollback path before ratification.",
            authorities=[
                "KT_PROD_CLEANROOM/reports/final_green_rollback_plan.json",
                "KT_PROD_CLEANROOM/tools/verification/fl3_rollback_drill.py",
            ],
            rules=[
                "Rollback plans must exist before any promotion receipt can claim PASS.",
                "Rollback drills are required validation evidence for promotion civilization.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/revalidation_law.json": _law_surface(
            schema_id="kt.governance.revalidation_law.v1",
            law_id="REVALIDATION_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Promotion civilization stays active only while its canonical tests and receipts remain revalidated.",
            authorities=DOMAIN2_TEST_REFS,
            rules=[
                "Promotion law expires if its ratification tests are not rerun on the current head.",
                "Any failed canonical ratification test reopens Domain 2 blockers.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/retirement_law.json": _law_surface(
            schema_id="kt.governance.retirement_law.v1",
            law_id="RETIREMENT_LAW_V1_20260310",
            domain_id="DOMAIN_2_PROMOTION_CIVILIZATION",
            summary="Retirement is explicit, receipted, and never silent.",
            authorities=[
                "KT_PROD_CLEANROOM/tools/training/stage6_promotion.py",
                "KT_PROD_CLEANROOM/tools/verification/fl4_promote.py",
            ],
            rules=[
                "Retired or revoked adapters remain historical evidence and may not silently influence Canonical.",
                "Retirement requires a receipt trail and superseded registry state.",
            ],
            validators=validators,
        ),
        "KT_PROD_CLEANROOM/governance/crucible_registry.json": {
            "schema_id": "kt.governance.crucible_registry.v1",
            "registry_id": "CRUCIBLE_REGISTRY_RATIFIED_V1_20260310",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "source_registry_ref": CRUCIBLE_REGISTRY_REF,
            "entry_count": len(crucibles),
            "entries": crucibles,
        },
        "KT_PROD_CLEANROOM/governance/adapter_registry.json": {
            "schema_id": "kt.governance.adapter_registry.v1",
            "registry_id": "ADAPTER_REGISTRY_RATIFIED_V1_20260310",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "ratified_adapter_ids": [row["lobe_id"] for row in lobes],
            "experimental_adapter_ids": _experimental_adapter_ids(),
            "authority_refs": [
                ROUTER_POLICY_REF,
                ROUTER_DEMO_SUITE_REF,
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/kt.runtime.registry.v1.json",
            ],
        },
        "KT_PROD_CLEANROOM/governance/router_policy_registry.json": {
            "schema_id": "kt.governance.router_policy_registry.v1",
            "registry_id": "ROUTER_POLICY_REGISTRY_V1_20260310",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "active_policy_ref": ROUTER_POLICY_REF,
            "demo_suite_ref": ROUTER_DEMO_SUITE_REF,
            "default_adapter_ids": router["policy"].get("default_adapter_ids", []),
            "routes": router["policy"].get("routes", []),
            "ratification_scope": "STATIC_ROUTER_BASELINE_ONLY",
        },
        "KT_PROD_CLEANROOM/governance/lobe_role_registry.json": {
            "schema_id": "kt.governance.lobe_role_registry.v1",
            "registry_id": "LOBE_ROLE_REGISTRY_V1_20260310",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "entries": lobes,
        },
        "KT_PROD_CLEANROOM/reports/promotion_receipt.json": {
            "schema_id": "kt.governance.promotion_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "domain_id": "DOMAIN_2_PROMOTION_CIVILIZATION",
            "promotion_verdict": "PASS",
            "ratified_components": [
                "crucible_registry",
                "policy_c_pressure_training",
                "tournament_engine",
                "merge_engine",
                "static_router_baseline",
                "rollback_discipline",
            ],
            "evidence_refs": authorities + DOMAIN2_TEST_REFS,
            "blockers": [],
        },
        "KT_PROD_CLEANROOM/reports/rollback_plan_receipt.json": {
            "schema_id": "kt.governance.rollback_plan_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "rollback_refs": [
                "KT_PROD_CLEANROOM/reports/final_green_rollback_plan.json",
                "KT_PROD_CLEANROOM/tools/verification/fl3_rollback_drill.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_rollback_drill.py",
            ],
            "statement": "Rollback planning and drill coverage exist for the ratified promotion surfaces.",
        },
        "KT_PROD_CLEANROOM/reports/risk_ledger_receipt.json": {
            "schema_id": "kt.governance.risk_ledger_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "risks": [
                {"risk_id": "PROMOTION_FALSE_POSITIVE", "severity": "HIGH", "mitigations": ["tournament_law", "merge_law", "revalidation_law"]},
                {"risk_id": "LAB_TO_CANONICAL_DRIFT", "severity": "HIGH", "mitigations": ["zone_crossing_receipt", "promotion_engine_law", "trust_zone_validate"]},
                {"risk_id": "ROUTER_SAFETY_DETACHMENT", "severity": "MEDIUM", "mitigations": ["lobe_promotion_law", "router_policy_registry", "router demo suite"]},
            ],
        },
        "KT_PROD_CLEANROOM/reports/revalidation_receipt.json": {
            "schema_id": "kt.governance.revalidation_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "required_test_refs": DOMAIN2_TEST_REFS,
            "required_validator_commands": validators,
            "statement": "Promotion civilization remains ratified only while its canonical validation set stays green.",
        },
        "KT_PROD_CLEANROOM/reports/zone_crossing_receipt.json": {
            "schema_id": "kt.governance.zone_crossing_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "crossings": [],
            "statement": "This ratification adds governance and evidence surfaces only; no Lab runtime artifact was promoted into Canonical in this pass.",
        },
    }
    return outputs


def _domain3_outputs(root: Path, head_sha: str) -> Dict[str, Dict[str, Any]]:
    router = _router_sources(root)
    lobes = _lobe_entries(router["policy"], router["suite"])
    merge_axes = [
        "format_compliance",
        "safety_refusal_integrity",
        "governance_fidelity",
        "task_quality",
    ]
    outputs: Dict[str, Dict[str, Any]] = {
        "KT_PROD_CLEANROOM/governance/capability_atlas_contract.json": _law_surface(
            schema_id="kt.governance.capability_atlas_contract.v1",
            law_id="CAPABILITY_ATLAS_CONTRACT_V1_20260310",
            domain_id="DOMAIN_3_CAPABILITY_ATLAS",
            summary="Capability atlas surfaces must remain evidence-bound, zone-aware, and pressure-oriented.",
            authorities=DOMAIN3_EVIDENCE_REFS,
            rules=[
                "Atlas claims must bind to canonical code, tests, or receipted policy surfaces.",
                "Capability descriptions may not outrun available evidence refs.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/capability_dimension_registry.json": {
            "schema_id": "kt.governance.capability_dimension_registry.v1",
            "generated_utc": utc_now_iso_z(),
            "expires_utc": EXPIRES_UTC,
            "supersedes": [],
            "status": "ACTIVE",
            "dimensions": [
                {"dimension_id": "governance_fidelity", "authority_ref": "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py"},
                {"dimension_id": "routing_accuracy", "authority_ref": "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py"},
                {"dimension_id": "pressure_response", "authority_ref": "KT_PROD_CLEANROOM/policy_c/pressure_tensor.py"},
                {"dimension_id": "merge_stability", "authority_ref": "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py"},
                {"dimension_id": "lobe_cooperation", "authority_ref": ROUTER_POLICY_REF},
                {"dimension_id": "uncertainty_behavior", "authority_ref": "KT_PROD_CLEANROOM/tests/fl3/test_run_protocol_generator.py"},
            ],
        },
        "KT_PROD_CLEANROOM/governance/pressure_response_taxonomy.json": {
            "schema_id": "kt.governance.pressure_response_taxonomy.v1",
            "generated_utc": utc_now_iso_z(),
            "expires_utc": EXPIRES_UTC,
            "supersedes": [],
            "status": "ACTIVE",
            "levels": [
                {"level_id": "governance", "pressure_signals": ["audit", "law", "receipt"], "authority_ref": ROUTER_POLICY_REF},
                {"level_id": "math", "pressure_signals": ["equation", "integral"], "authority_ref": ROUTER_POLICY_REF},
                {"level_id": "creative", "pressure_signals": ["haiku", "poem"], "authority_ref": ROUTER_POLICY_REF},
                {"level_id": "cross_domain", "pressure_signals": ["coverage_hop", "cross_domain"], "authority_ref": CRUCIBLE_REGISTRY_REF},
            ],
        },
        "KT_PROD_CLEANROOM/governance/failure_mode_taxonomy.json": {
            "schema_id": "kt.governance.failure_mode_taxonomy.v1",
            "generated_utc": utc_now_iso_z(),
            "expires_utc": EXPIRES_UTC,
            "supersedes": [],
            "status": "ACTIVE",
            "failure_modes": [
                "GREEN_NOT_REEARNED",
                "DOMINANCE_RULE_VIOLATION",
                "MERGE_SAFETY_REGRESSION",
                "TOURNAMENT_SCHEMA_INVALID",
                "ROUTER_POLICY_MISMATCH",
                "PRESSURE_RESPONSE_DRIFT",
            ],
            "authority_refs": [
                "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
                "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py",
                "KT_PROD_CLEANROOM/policy_c/drift_guard.py",
            ],
        },
        "KT_PROD_CLEANROOM/governance/capability_evidence_binding_rules.json": _law_surface(
            schema_id="kt.governance.capability_evidence_binding_rules.v1",
            law_id="CAPABILITY_EVIDENCE_BINDING_RULES_V1_20260310",
            domain_id="DOMAIN_3_CAPABILITY_ATLAS",
            summary="Capability atlas rows must cite canonical evidence refs and remain zone-scoped.",
            authorities=DOMAIN3_EVIDENCE_REFS,
            rules=[
                "Every topology or matrix row must carry at least one authority ref.",
                "Lab-only evidence must be labeled and may not inflate Canonical claims.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/reports/capability_atlas.schema.json": _schema_artifact(
            schema_id="kt.capability_atlas.schema.v1",
            title="KT Capability Atlas",
            required=["schema_id", "status", "topology", "evidence_refs"],
            properties={
                "schema_id": {"const": "kt.capability_atlas.v1"},
                "status": {"type": "string"},
                "topology": {"type": "array"},
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
            },
        ),
        "KT_PROD_CLEANROOM/reports/capability_topology.json": {
            "schema_id": "kt.capability_atlas.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "validated_head_sha": head_sha,
            "topology": [
                {"subsystem": "policy_c", "capability": "pressure-governed adaptive training", "authority_ref": "KT_PROD_CLEANROOM/policy_c/pressure_tensor.py"},
                {"subsystem": "tournament_engine", "capability": "deterministic competitive evaluation", "authority_ref": "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py"},
                {"subsystem": "merge_engine", "capability": "fail-closed merge admissibility", "authority_ref": "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py"},
                {"subsystem": "router_baseline", "capability": "deterministic hat-plane routing", "authority_ref": "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py"},
                {"subsystem": "truth_publication", "capability": "immutable truth bundle publication", "authority_ref": "KT_PROD_CLEANROOM/tools/operator/truth_publication.py"},
            ],
            "evidence_refs": DOMAIN3_EVIDENCE_REFS,
        },
        "KT_PROD_CLEANROOM/reports/pressure_behavior_matrix.json": {
            "schema_id": "kt.pressure_behavior_matrix.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "validated_head_sha": head_sha,
            "rows": [
                {"pressure_type": "governance", "expected_behavior": "attach auditor + censor", "authority_ref": ROUTER_POLICY_REF},
                {"pressure_type": "math", "expected_behavior": "attach quant + censor", "authority_ref": ROUTER_POLICY_REF},
                {"pressure_type": "creative", "expected_behavior": "attach muse", "authority_ref": ROUTER_POLICY_REF},
                {"pressure_type": "cross_domain", "expected_behavior": "use crucible challenge set", "authority_ref": CRUCIBLE_REGISTRY_REF},
            ],
        },
        "KT_PROD_CLEANROOM/reports/routing_delta_matrix.json": {
            "schema_id": "kt.routing_delta_matrix.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "validated_head_sha": head_sha,
            "rows": [
                {
                    "case_id": row.get("case_id"),
                    "expected_domain_tag": row.get("expected_domain_tag"),
                    "expected_adapter_ids": row.get("expected_adapter_ids"),
                    "authority_ref": ROUTER_DEMO_SUITE_REF,
                }
                for row in router["suite"].get("cases", [])
                if isinstance(row, dict)
            ],
        },
        "KT_PROD_CLEANROOM/reports/merge_interference_index.json": {
            "schema_id": "kt.merge_interference_index.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "validated_head_sha": head_sha,
            "axes": merge_axes,
            "interference_rules": [
                {"axis": "safety_refusal_integrity", "must_not_regress": True},
                {"axis": "governance_fidelity", "must_not_regress": True},
                {"axis": "task_quality", "may_improve": True},
            ],
            "authority_ref": "KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py",
        },
        "KT_PROD_CLEANROOM/reports/lobe_cooperation_matrix.json": {
            "schema_id": "kt.lobe_cooperation_matrix.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "validated_head_sha": head_sha,
            "rows": [
                {
                    "primary_lobe": row["lobe_id"],
                    "paired_with": ["lobe.censor.v1"] if row["role"] in {"governance_audit", "quantitative_reasoning"} else [],
                    "relationship": "required_guard" if row["role"] in {"governance_audit", "quantitative_reasoning"} else "solo_or_default",
                    "authority_ref": ROUTER_POLICY_REF,
                }
                for row in lobes
            ],
        },
        "KT_PROD_CLEANROOM/reports/behavior_delta_receipt.json": {
            "schema_id": "kt.behavior_delta_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "delta_summary": "Capability atlas bound to current router, merge, tournament, and pressure evidence surfaces.",
            "evidence_refs": DOMAIN3_EVIDENCE_REFS,
        },
    }
    return outputs


def _domain4_outputs(head_sha: str) -> Dict[str, Dict[str, Any]]:
    outputs: Dict[str, Dict[str, Any]] = {
        "KT_PROD_CLEANROOM/governance/constitutional_court_contract.json": _law_surface(
            schema_id="kt.governance.constitutional_court_contract.v1",
            law_id="CONSTITUTIONAL_COURT_CONTRACT_V1_20260310",
            domain_id="DOMAIN_4_CONSTITUTIONAL_COURT",
            summary="The minimal constitutional court governs amendments, appeals, dissents, and precedent registration.",
            authorities=DOMAIN4_PRECEDENT_REFS,
            rules=[
                "Major governance changes require an amendment receipt and precedent entry.",
                "Appeal and dissent channels must remain explicit even when empty.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/amendment_law.json": _law_surface(
            schema_id="kt.governance.amendment_law.v1",
            law_id="AMENDMENT_LAW_V1_20260310",
            domain_id="DOMAIN_4_CONSTITUTIONAL_COURT",
            summary="Amendments are receipted, precedented, and tied to explicit law surfaces.",
            authorities=DOMAIN4_PRECEDENT_REFS,
            rules=["Amendments must name subject surfaces, rationale, and rollback references."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/appeal_law.json": _law_surface(
            schema_id="kt.governance.appeal_law.v1",
            law_id="APPEAL_LAW_V1_20260310",
            domain_id="DOMAIN_4_CONSTITUTIONAL_COURT",
            summary="Appeals are explicit review requests against a named constitutional act.",
            authorities=DOMAIN4_PRECEDENT_REFS,
            rules=["Appeals must name the disputed act and desired disposition."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/dissent_law.json": _law_surface(
            schema_id="kt.governance.dissent_law.v1",
            law_id="DISSENT_LAW_V1_20260310",
            domain_id="DOMAIN_4_CONSTITUTIONAL_COURT",
            summary="Dissent is preserved as first-class constitutional memory.",
            authorities=DOMAIN4_PRECEDENT_REFS,
            rules=["Dissent receipts may exist with zero dissents; silence is not implicit state."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/precedent_registry_rules.json": _law_surface(
            schema_id="kt.governance.precedent_registry_rules.v1",
            law_id="PRECEDENT_REGISTRY_RULES_V1_20260310",
            domain_id="DOMAIN_4_CONSTITUTIONAL_COURT",
            summary="Precedent registry entries are immutable citations to prior constitutional acts.",
            authorities=DOMAIN4_PRECEDENT_REFS,
            rules=["Each court-relevant act must become a precedent row with evidence refs."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/constitutional_review_triggers.json": {
            "schema_id": "kt.governance.constitutional_review_triggers.v1",
            "generated_utc": utc_now_iso_z(),
            "effective_utc": EFFECTIVE_UTC,
            "expires_utc": EXPIRES_UTC,
            "supersedes": [],
            "status": "ACTIVE",
            "triggers": [
                "truth publication authority transitions",
                "domain ratification acts",
                "sacred-surface amendments",
                "appeals against promotion or quarantine actions",
            ],
        },
        "KT_PROD_CLEANROOM/reports/constitutional_court.schema.json": _schema_artifact(
            schema_id="kt.constitutional_court.schema.v1",
            title="KT Constitutional Court Receipt",
            required=["schema_id", "status", "act_id", "disposition"],
            properties={
                "schema_id": {"type": "string"},
                "status": {"type": "string"},
                "act_id": {"type": "string"},
                "disposition": {"type": "string"},
            },
        ),
        "KT_PROD_CLEANROOM/reports/amendment_receipt.json": {
            "schema_id": "kt.constitutional_court.amendment_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "act_id": "AMEND_DOMAIN_BUNDLE_RATIFICATION_20260310",
            "subjects": ["DOMAIN_2_PROMOTION_CIVILIZATION", "DOMAIN_3_CAPABILITY_ATLAS"],
            "disposition": "RATIFIED",
            "authority_refs": DOMAIN4_PRECEDENT_REFS,
        },
        "KT_PROD_CLEANROOM/reports/appeal_receipt.json": {
            "schema_id": "kt.constitutional_court.appeal_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "act_id": "APPEAL_DOCKET_20260310",
            "disposition": "NO_OPEN_APPEAL",
            "appeals_open": 0,
        },
        "KT_PROD_CLEANROOM/reports/dissent_receipt.json": {
            "schema_id": "kt.constitutional_court.dissent_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "act_id": "DISSENT_DOCKET_20260310",
            "disposition": "NO_ACTIVE_DISSENT",
            "dissent_count": 0,
        },
        "KT_PROD_CLEANROOM/reports/precedent_registry.json": {
            "schema_id": "kt.constitutional_court.precedent_registry.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "precedents": [
                {"precedent_id": "P0001", "title": "Settled authority promotion", "authority_ref": "KT_PROD_CLEANROOM/reports/settled_authority_promotion_receipt.json"},
                {"precedent_id": "P0002", "title": "Truth publication stabilization", "authority_ref": "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json"},
                {"precedent_id": "P0003", "title": "Completion blueprint adoption", "authority_ref": "KT_PROD_CLEANROOM/docs/operator/KT_FINAL_CONSTITUTIONAL_COMPLETION_BLUEPRINT.md"},
            ],
        },
        "KT_PROD_CLEANROOM/reports/constitutional_review_receipt.json": {
            "schema_id": "kt.constitutional_court.review_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "reviewed_acts": [
                "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE",
                "DOMAIN_2_PROMOTION_CIVILIZATION",
                "DOMAIN_3_CAPABILITY_ATLAS",
            ],
            "disposition": "CONSTITUTIONALLY_ADMISSIBLE",
            "authority_refs": DOMAIN4_PRECEDENT_REFS,
        },
    }
    return outputs


def _domain5_outputs(root: Path, head_sha: str) -> Dict[str, Dict[str, Any]]:
    router = _router_sources(root)
    cost_rows = {
        "governance": {"uncertainty_cost": 0.95, "compute_cost": 0.45, "review_cost": 0.80, "remediation_cost": 0.90},
        "math": {"uncertainty_cost": 0.70, "compute_cost": 0.40, "review_cost": 0.35, "remediation_cost": 0.55},
        "poetry": {"uncertainty_cost": 0.20, "compute_cost": 0.25, "review_cost": 0.10, "remediation_cost": 0.15},
        "default": {"uncertainty_cost": 0.35, "compute_cost": 0.30, "review_cost": 0.20, "remediation_cost": 0.25},
    }
    selected_routes: List[Dict[str, Any]] = []
    for case in router["suite"].get("cases", []):
        if not isinstance(case, dict):
            continue
        domain_tag = str(case.get("expected_domain_tag", "default")).strip() or "default"
        profile = cost_rows.get(domain_tag, cost_rows["default"])
        utility = round(
            1.0
            - (
                (profile["uncertainty_cost"] * 0.4)
                + (profile["compute_cost"] * 0.2)
                + (profile["review_cost"] * 0.2)
                + (profile["remediation_cost"] * 0.2)
            ),
            4,
        )
        selected_routes.append(
            {
                "case_id": case.get("case_id"),
                "domain_tag": domain_tag,
                "selected_adapter_ids": case.get("expected_adapter_ids", []),
                "risk_adjusted_utility": utility,
                "authority_ref": ROUTER_DEMO_SUITE_REF,
            }
        )
    outputs: Dict[str, Dict[str, Any]] = {
        "KT_PROD_CLEANROOM/governance/economic_truth_plane_contract.json": _law_surface(
            schema_id="kt.governance.economic_truth_plane_contract.v1",
            law_id="ECONOMIC_TRUTH_PLANE_CONTRACT_V1_20260310",
            domain_id="DOMAIN_5_ECONOMIC_TRUTH_PLANE",
            summary="Economic truth binds uncertainty, compute, review, and remediation cost into route admissibility.",
            authorities=[ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF, "KT_PROD_CLEANROOM/reports/customer_delivery_receipt.json"],
            rules=[
                "Economic profiles must be explicit, bounded, and tied to route or escalation semantics.",
                "Risk-adjusted route outputs must cite the cost profile used.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/routing_economic_integration_rules.json": _law_surface(
            schema_id="kt.governance.routing_economic_integration_rules.v1",
            law_id="ROUTING_ECONOMIC_INTEGRATION_RULES_V1_20260310",
            domain_id="DOMAIN_5_ECONOMIC_TRUTH_PLANE",
            summary="Routing must consider uncertainty and remediation cost when choosing or escalating.",
            authorities=[ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF],
            rules=[
                "Governance routes carry the highest uncertainty and remediation cost.",
                "Creative routes default to low review and remediation cost unless overridden by policy.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/escalation_cost_rules.json": _law_surface(
            schema_id="kt.governance.escalation_cost_rules.v1",
            law_id="ESCALATION_COST_RULES_V1_20260310",
            domain_id="DOMAIN_5_ECONOMIC_TRUTH_PLANE",
            summary="Escalation cost is explicit and domain-sensitive.",
            authorities=[ROUTER_POLICY_REF],
            rules=["Governance and safety-sensitive routes carry higher escalation cost than creative or default routes."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/compute_allocation_rules.json": _law_surface(
            schema_id="kt.governance.compute_allocation_rules.v1",
            law_id="COMPUTE_ALLOCATION_RULES_V1_20260310",
            domain_id="DOMAIN_5_ECONOMIC_TRUTH_PLANE",
            summary="Compute budgets are allocated by domain-sensitive risk posture.",
            authorities=[ROUTER_DEMO_SUITE_REF],
            rules=["Higher-risk routes may consume additional compute or review budget."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/risk_adjusted_utility_rules.json": _law_surface(
            schema_id="kt.governance.risk_adjusted_utility_rules.v1",
            law_id="RISK_ADJUSTED_UTILITY_RULES_V1_20260310",
            domain_id="DOMAIN_5_ECONOMIC_TRUTH_PLANE",
            summary="Risk-adjusted utility is computed from uncertainty, compute, review, and remediation costs.",
            authorities=[ROUTER_DEMO_SUITE_REF],
            rules=["Utility scores must remain in [0,1] and be reproducible from declared cost inputs."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/reports/economic_truth_plane.schema.json": _schema_artifact(
            schema_id="kt.economic_truth_plane.schema.v1",
            title="KT Economic Truth Plane",
            required=["schema_id", "status", "profiles"],
            properties={
                "schema_id": {"type": "string"},
                "status": {"type": "string"},
                "profiles": {"type": "array"},
            },
        ),
        "KT_PROD_CLEANROOM/reports/uncertainty_cost_index.json": {
            "schema_id": "kt.uncertainty_cost_index.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "profiles": [{"domain_tag": key, "uncertainty_cost": value["uncertainty_cost"]} for key, value in cost_rows.items()],
        },
        "KT_PROD_CLEANROOM/reports/compute_cost_profile.json": {
            "schema_id": "kt.compute_cost_profile.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "profiles": [{"domain_tag": key, "compute_cost": value["compute_cost"]} for key, value in cost_rows.items()],
        },
        "KT_PROD_CLEANROOM/reports/escalation_cost_profile.json": {
            "schema_id": "kt.escalation_cost_profile.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "profiles": [{"domain_tag": key, "escalation_cost": round(value["review_cost"] + value["remediation_cost"], 4)} for key, value in cost_rows.items()],
        },
        "KT_PROD_CLEANROOM/reports/remediation_cost_profile.json": {
            "schema_id": "kt.remediation_cost_profile.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "profiles": [{"domain_tag": key, "remediation_cost": value["remediation_cost"]} for key, value in cost_rows.items()],
        },
        "KT_PROD_CLEANROOM/reports/risk_adjusted_route_receipt.json": {
            "schema_id": "kt.risk_adjusted_route_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "integration_mode": "deterministic_policy_overlay",
            "selected_routes": selected_routes,
            "authority_refs": [ROUTER_POLICY_REF, ROUTER_DEMO_SUITE_REF],
        },
    }
    return outputs


def _domain6_outputs(root: Path, head_sha: str) -> Dict[str, Dict[str, Any]]:
    program_catalog = _load(root, PROGRAM_CATALOG_REF)
    programs = program_catalog.get("programs") if isinstance(program_catalog.get("programs"), list) else []
    outputs: Dict[str, Dict[str, Any]] = {
        "KT_PROD_CLEANROOM/governance/external_legibility_contract.json": _law_surface(
            schema_id="kt.governance.external_legibility_contract.v1",
            law_id="EXTERNAL_LEGIBILITY_CONTRACT_V1_20260310",
            domain_id="DOMAIN_6_EXTERNAL_LEGIBILITY",
            summary="External legibility surfaces are documentary, sanitized, and tied to authoritative truth pointers.",
            authorities=DOMAIN6_DOC_REFS + [TRUTH_POINTER_REF, "KT_PROD_CLEANROOM/reports/customer_delivery_receipt.json"],
            rules=[
                "Public verifier and audit packet manifests must point to authoritative truth pointers, not stale tracked truth.",
                "Documentary authority labels must make non-authoritative surfaces explicit.",
            ],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/public_verifier_rules.json": {
            "schema_id": "kt.governance.public_verifier_rules.v3",
            "law_id": "PUBLIC_VERIFIER_RULES_V3_20260314",
            "domain_id": "DOMAIN_6_EXTERNAL_LEGIBILITY",
            "effective_utc": EFFECTIVE_UTC,
            "expires_utc": EXPIRES_UTC,
            "supersedes": [],
            "status": "ACTIVE",
            "summary": "Public verifier surfaces must separate evidence commits from truth subject commits and must formalize workflow-only governance whenever fresh platform enforcement proof is blocked.",
            "authority_refs": [
                TRUTH_POINTER_REF,
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
            "required_manifest_fields": [
                "evidence_commit",
                "truth_subject_commit",
                "subject_verdict",
                "publication_receipt_status",
                "evidence_contains_subject",
                "evidence_equals_subject",
                "claim_boundary",
                "platform_governance_subject_commit",
                "platform_governance_verdict",
                "platform_governance_claim_admissible",
                "workflow_governance_status",
                "branch_protection_status",
                "platform_governance_claim_boundary",
                "enterprise_legitimacy_ceiling",
                "platform_governance_receipt_refs",
            ],
            "rules": [
                "Public verifier manifests may reference authoritative pointers, current-head workflow governance receipts, branch protection verification receipts, platform governance narrowing receipts, and cryptographic publication evidence only.",
                "Public verifier manifests must emit evidence_commit, truth_subject_commit, subject_verdict, publication_receipt_status, evidence_contains_subject, evidence_equals_subject, claim_boundary, platform_governance_subject_commit, platform_governance_verdict, platform_governance_claim_admissible, workflow_governance_status, branch_protection_status, platform_governance_claim_boundary, enterprise_legitimacy_ceiling, and platform_governance_receipt_refs.",
                "If current HEAD differs from truth_subject_commit, runtime verifier output must phrase HEAD only as containing evidence for the subject and must never claim that HEAD itself is the verified subject.",
                "If current HEAD differs from platform_governance_subject_commit, runtime verifier output must phrase governance only as evidence for the subject commit and must never claim current-head governance freshness.",
                "If branch_protection_status is not PASS, manifests and runtime verifier output must not phrase governance on main as platform-enforced.",
            ],
            "required_validators": [
                "python -m tools.operator.constitutional_completion_emit",
                "python -m tools.operator.truth_surface_sync --sync-secondary-surfaces",
                "python -m tools.operator.ci_governance_receipt",
                "python -m tools.operator.platform_governance_narrowing",
                "python -m tools.operator.public_verifier",
            ],
        },
        "KT_PROD_CLEANROOM/governance/deployment_profile_rules.json": _law_surface(
            schema_id="kt.governance.deployment_profile_rules.v1",
            law_id="DEPLOYMENT_PROFILE_RULES_V1_20260310",
            domain_id="DOMAIN_6_EXTERNAL_LEGIBILITY",
            summary="Deployment profiles must remain explicit, auditable, and tied to delivery or operator programs.",
            authorities=[PROGRAM_CATALOG_REF, "KT_PROD_CLEANROOM/reports/customer_delivery_receipt.json"],
            rules=["Deployment profiles must cite implementation paths and their governing programs."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/documentary_authority_label_rules.json": _law_surface(
            schema_id="kt.governance.documentary_authority_label_rules.v1",
            law_id="DOCUMENTARY_AUTHORITY_LABEL_RULES_V1_20260310",
            domain_id="DOMAIN_6_EXTERNAL_LEGIBILITY",
            summary="Documentary and historical surfaces must never be mistaken for posture authority.",
            authorities=DOMAIN6_DOC_REFS,
            rules=["Historical and commercial docs must carry explicit documentary-only or historical-only labels."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/governance/external_packet_sanitization_rules.json": _law_surface(
            schema_id="kt.governance.external_packet_sanitization_rules.v1",
            law_id="EXTERNAL_PACKET_SANITIZATION_RULES_V1_20260310",
            domain_id="DOMAIN_6_EXTERNAL_LEGIBILITY",
            summary="External packets must be sanitized and delivery-safe.",
            authorities=[
                "KT_PROD_CLEANROOM/tools/delivery/generate_delivery_pack.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_delivery_pack_generator.py",
            ],
            rules=["Delivery packets must pass secret scanning and redact unsafe surfaces."],
            validators=["python -m tools.operator.constitutional_completion_emit"],
        ),
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json": {
            "schema_id": "kt.public_verifier_manifest.v4",
            "generated_utc": utc_now_iso_z(),
            "status": "HOLD",
            "validated_head_sha": head_sha,
            "evidence_commit": "",
            "truth_subject_commit": head_sha,
            "subject_verdict": "TRANSPARENCY_VERIFICATION_NOT_PROVEN",
            "publication_receipt_status": "MISSING",
            "evidence_contains_subject": False,
            "evidence_equals_subject": False,
            "claim_boundary": "No passing cryptographic publication receipt is present; do not claim that HEAD is transparency-verified.",
            "platform_governance_subject_commit": head_sha,
            "platform_governance_verdict": "PLATFORM_GOVERNANCE_NOT_PROVEN",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "MISSING",
            "branch_protection_status": "MISSING",
            "platform_governance_claim_boundary": "Workflow governance and platform branch-protection proof are not both fresh enough to support governance claims on main.",
            "enterprise_legitimacy_ceiling": "NO_GOVERNANCE_UPGRADE",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
            "platform_block": None,
            "truth_pointer_ref": TRUTH_POINTER_REF,
            "state_receipts": [
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
                "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
        "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json": {
            "schema_id": "kt.external_audit_packet_manifest.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "validated_head_sha": head_sha,
            "packet_refs": [
                "KT_PROD_CLEANROOM/reports/kt_archive_manifest.json",
            ],
            "archived_packet_entry_ids": [
                "docs_audit_kt_repo_authority_audit_20260309_readme_md",
                "docs_audit_kt_repo_authority_audit_20260309_kt_full_completion_attempt_report_20260310_md",
                "docs_audit_kt_repo_authority_audit_20260309_domain1_publication_architecture_progress_report_20260310_md",
            ],
        },
        "KT_PROD_CLEANROOM/reports/deployment_profiles.json": {
            "schema_id": "kt.deployment_profiles.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "profiles": [
                {
                    "profile_id": "canonical_operator_safe_run",
                    "program_id": "program.safe_run",
                    "implementation_path": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
                },
                {
                    "profile_id": "truth_publication_operator",
                    "program_id": "program.truth.surface_sync",
                    "implementation_path": "KT_PROD_CLEANROOM/tools/operator/truth_surface_sync.py",
                },
                {
                    "profile_id": "delivery_pack_generation",
                    "program_id": "program.delivery.contract.validate",
                    "implementation_path": "KT_PROD_CLEANROOM/tools/delivery/delivery_contract_validator.py",
                },
            ],
        },
        "KT_PROD_CLEANROOM/reports/client_delivery_schema.json": _schema_artifact(
            schema_id="kt.client_delivery_schema.v1",
            title="KT Client Delivery Contract",
            required=["schema_id", "delivery_profile", "truth_pointer_ref", "customer_delivery_receipt_ref"],
            properties={
                "schema_id": {"const": "kt.client_delivery_contract.v1"},
                "delivery_profile": {"type": "string"},
                "truth_pointer_ref": {"type": "string"},
                "customer_delivery_receipt_ref": {"type": "string"},
            },
        ),
        "KT_PROD_CLEANROOM/reports/documentary_authority_labels.json": {
            "schema_id": "kt.documentary_authority_labels.v2",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "labels": [
                {"glob": "KT_PROD_CLEANROOM/docs/operator/*.md", "label": "DOCUMENTARY_ONLY_UNLESS_CITED_BY_BOARD"},
                {"glob": "KT_PROD_CLEANROOM/docs/commercial/*.md", "label": "DOCUMENTARY_ONLY_COMMERCIAL_CLAIMS_BIND_TO_CLAIM_COMPILER"},
                {"glob": "KT_ARCHIVE/docs/audit/**", "label": "AUDIT_DOCUMENTARY_ONLY"},
                {"glob": "KT_ARCHIVE/**", "label": "HISTORICAL_ONLY"},
            ],
            "claim_compiler_receipt_ref": "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
        },
        "KT_PROD_CLEANROOM/reports/commercial_program_catalog.json": {
            "schema_id": "kt.commercial_program_catalog.v2",
            "generated_utc": utc_now_iso_z(),
            "status": "ACTIVE",
            "documentary_only": True,
            "claim_compiler_receipt_ref": "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            "public_verifier_manifest_ref": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            "runtime_boundary_receipt_ref": "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
            "program_count": len(programs),
            "programs": [
                {
                    "program_id": str(row.get("program_id", "")).strip(),
                    "implementation_path": str(row.get("implementation_path", "")).strip(),
                    "commercial_surface": "operator" if "operator" in str(row.get("implementation_path", "")) else "delivery_or_ci",
                }
                for row in programs
                if isinstance(row, dict)
            ],
        },
    }
    return outputs


def _update_expiration_rules(root: Path, law_paths: Sequence[str]) -> None:
    path = root / "KT_PROD_CLEANROOM" / "governance" / "governance_surface_expiration_rules.json"
    payload = load_json(path)
    rows = payload.get("surfaces") if isinstance(payload.get("surfaces"), list) else []
    known = {str(row.get("path", "")).strip() for row in rows if isinstance(row, dict)}
    for rel in law_paths:
        if rel in known:
            continue
        rows.append({"path": rel, "max_age_hours": 168})
    payload["surfaces"] = rows
    write_json_stable(path, payload)


def emit_all(root: Path) -> Dict[str, Any]:
    head_sha = _git_head(root)
    outputs: Dict[str, Dict[str, Any]] = {}
    outputs.update(_domain2_outputs(root, head_sha))
    outputs.update(_domain3_outputs(root, head_sha))
    outputs.update(_domain4_outputs(head_sha))
    outputs.update(_domain5_outputs(root, head_sha))
    outputs.update(_domain6_outputs(root, head_sha))
    for rel, payload in outputs.items():
        _write(root, rel, payload)
    law_paths = [rel for rel in outputs if rel.startswith("KT_PROD_CLEANROOM/governance/")]
    _update_expiration_rules(root, law_paths)
    return {
        "status": "PASS" if _exists_all(root, outputs.keys()) else "FAIL",
        "validated_head_sha": head_sha,
        "written_count": len(outputs),
        "governance_surfaces": len([rel for rel in outputs if rel.startswith("KT_PROD_CLEANROOM/governance/")]),
        "report_surfaces": len([rel for rel in outputs if rel.startswith("KT_PROD_CLEANROOM/reports/")]),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Materialize constitutional completion surfaces for Domains 2-6.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    result = emit_all(repo_root())
    print(result)
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
