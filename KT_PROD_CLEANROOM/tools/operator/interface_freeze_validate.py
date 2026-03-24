from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_OUTPUT_REL = "KT_PROD_CLEANROOM/reports/kt_wave0_5_interface_freeze_receipt.json"
FROZEN_STATUS = "FROZEN_WAVE_0_5"

INTERFACE_CONTRACT_SPECS: Dict[str, Dict[str, Any]] = {
    "KT_PROD_CLEANROOM/governance/kt_organ_contract_v1.json": {
        "schema_id": "kt.governance.organ_contract.v1",
        "required_lists": {
            "required_fields": [
                "organ_id",
                "zone",
                "canonical_entrypoint",
                "invocation_contract",
                "preconditions",
                "telemetry_envelope_ref",
                "provenance_requirements",
                "failure_artifact_ref",
                "replay_pack_ref",
                "benchmark_pack_ref",
                "challenge_pack_ref",
                "promotion_gate",
                "rollback_semantics",
                "mutation_authority_ref",
                "status",
                "maturity_class",
            ],
            "required_behaviors": [
                "deterministic_failure_artifact_on_error",
                "fail_closed_if_preconditions_unmet",
                "telemetry_emission",
                "provenance_emission",
                "benchmarkability_declaration",
                "challengeability_declaration",
                "rollbackability_declaration",
            ],
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v1.json": {
        "schema_id": "kt.governance.adapter_abi.v1",
        "required_lists": {
            "required_fields": [
                "adapter_id",
                "adapter_kind",
                "version",
                "execution_mode",
                "policy_profile",
                "budget_profile",
                "provenance_requirements",
                "challenge_hooks",
                "provider_id",
                "timeout_ms",
                "retry_policy",
                "circuit_breaker_policy",
                "rate_limit_profile",
                "replayability_class",
                "status",
                "io_schema_ref",
            ],
            "execution_modes": ["DRY_RUN", "SHADOW", "LIVE", "ADVERSARIAL"],
            "hard_rules": [
                "all_external_providers_and_internal_plugin_style_integrations_must_speak_one_abi",
                "all_adapter_failures_must_emit_FailureArtifactV1",
            ],
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_failure_artifact_v1.json": {
        "schema_id": "kt.governance.failure_artifact.v1",
        "required_lists": {
            "required_fields": [
                "failure_id",
                "timestamp",
                "surface_id",
                "wave_id",
                "error_class",
                "bounded_reason",
                "input_hash",
                "context_hash",
                "policy_profile",
                "budget_profile",
                "replay_pack_ref",
                "operator_visibility",
                "severity",
                "signature_or_receipt_ref",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_telemetry_envelope_v1.json": {
        "schema_id": "kt.governance.telemetry_envelope.v1",
        "required_lists": {
            "required_fields": [
                "trace_id",
                "span_id",
                "request_id",
                "surface_id",
                "zone",
                "event_type",
                "start_ts",
                "end_ts",
                "latency_ms",
                "provider_id",
                "budget_consumed",
                "policy_applied",
                "result_status",
                "receipt_ref",
                "failure_artifact_ref",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_mutation_authority_v1.json": {
        "schema_id": "kt.governance.mutation_authority.v1",
        "required_lists": {
            "required_fields": [
                "surface_id",
                "writer_path",
                "writer_class",
                "may_mutate_state",
                "allowed_mutation_classes",
                "required_receipts",
                "rollback_law",
                "operator_authority_class",
                "forbidden_mutations",
            ],
            "binding_targets": [
                "state_vault_writes",
                "governance_event_writes",
                "release_truth_writes",
                "blocker_surface_recomputations",
                "state_core_recomputations",
                "claim_surface_recomputations",
                "product_truth_surface_recomputations",
            ],
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_challenge_pack_v1.json": {
        "schema_id": "kt.governance.challenge_pack.v1",
        "required_lists": {
            "required_fields": [
                "challenge_pack_id",
                "surface_id",
                "adversarial_probes",
                "expected_bounded_responses",
                "failure_classes",
                "regression_binding_rule",
                "replay_contract",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_deletion_law_v1.json": {
        "schema_id": "kt.governance.deletion_law.v1",
        "required_lists": {
            "required_fields": [
                "surface_id",
                "canonization_result",
                "post_decision_zone",
                "deletion_or_demotion_receipt",
                "historical_visibility_rule",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_benchmark_constitution_v1.json": {
        "schema_id": "kt.governance.benchmark_constitution.v1",
        "allowed_statuses": [FROZEN_STATUS, "FROZEN_W4_CURRENT_HEAD"],
        "required_lists": {
            "required_fields": [
                "dataset_registry",
                "holdout_policy",
                "comparator_policy",
                "contamination_policy",
                "cost_accounting_rule",
                "latency_accounting_rule",
                "failure_row_retention_rule",
                "replayability_coverage_rule",
                "adversarial_probe_coverage_rule",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_externality_class_matrix_v1.json": {
        "schema_id": "kt.governance.externality_class_matrix.v1",
        "required_lists": {
            "required_classes": [
                "E0_INTERNAL_SELF_ISSUED_ONLY",
                "E1_SAME_HOST_DETACHED_REPLAY",
                "E2_CROSS_HOST_FRIENDLY_REPLAY",
                "E3_INDEPENDENT_HOSTILE_REPLAY",
                "E4_PUBLIC_CHALLENGE_SURVIVAL",
            ]
        },
    },
    "KT_PROD_CLEANROOM/governance/kt_minimum_viable_civilization_run_v1.json": {
        "schema_id": "kt.governance.minimum_viable_civilization_run.v1",
        "required_lists": {
            "required_path": [
                "ingress",
                "router",
                "adapter_or_provider",
                "organ_stack",
                "state_vault",
                "verifier_pack",
                "claim_compiler",
                "bounded_output",
            ]
        },
    },
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def build_interface_freeze_receipt(*, root: Path) -> Dict[str, Any]:
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []
    frozen_refs: List[str] = []

    for relpath, spec in INTERFACE_CONTRACT_SPECS.items():
        path = (root / relpath).resolve()
        if not path.exists():
            failures.append(f"missing_contract:{relpath}")
            checks.append({"check": relpath, "status": "FAIL", "reason": "missing"})
            continue
        payload = load_json(path)
        frozen_refs.append(relpath)
        schema_ok = str(payload.get("schema_id", "")).strip() == str(spec.get("schema_id", "")).strip()
        allowed_statuses = [
            str(item).strip().upper()
            for item in spec.get("allowed_statuses", [FROZEN_STATUS])
            if str(item).strip()
        ]
        observed_status = str(payload.get("status", "")).strip().upper()
        status_ok = observed_status in allowed_statuses
        missing_lists: Dict[str, List[str]] = {}
        for key, expected_values in spec.get("required_lists", {}).items():
            actual = [str(item).strip() for item in payload.get(key, []) if str(item).strip()]
            missing = [value for value in expected_values if value not in actual]
            if missing:
                missing_lists[key] = missing
        check_status = "PASS" if schema_ok and status_ok and not missing_lists else "FAIL"
        checks.append(
            {
                "check": relpath,
                "status": check_status,
                "schema_ok": schema_ok,
                "status_ok": status_ok,
                "allowed_statuses": allowed_statuses,
                "observed_status": observed_status,
                "missing_lists": missing_lists,
            }
        )
        if not schema_ok:
            failures.append(f"schema_mismatch:{relpath}")
        if not status_ok:
            failures.append(f"status_not_frozen:{relpath}")
        for key, missing in missing_lists.items():
            failures.append(f"missing_{key}:{relpath}:{','.join(missing)}")

    status = "PASS" if not failures else "FAIL"
    return {
        "schema_id": "kt.operator.interface_freeze_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": _git_head(root),
        "wave_frozen": "WAVE_0_5_PACKAGE_IMPORT_CANON_AND_INTERFACE_FREEZE",
        "frozen_contract_refs": frozen_refs,
        "checks": checks,
        "failures": failures,
        "claim_boundary": "These frozen contracts bind interface law for later waves. They do not themselves elevate adapters, routing, organs, externality, or product truth.",
        "stronger_claim_not_made": [
            "adapter_activation_started",
            "router_elevation_started",
            "minimum_viable_civilization_run_executed",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate that Wave 0.5 interface contracts are present and frozen.")
    ap.add_argument("--output", default=DEFAULT_OUTPUT_REL)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    output = Path(str(args.output)).expanduser()
    if not output.is_absolute():
        output = (root / output).resolve()
    receipt = build_interface_freeze_receipt(root=root)
    write_json_stable(output, receipt)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
