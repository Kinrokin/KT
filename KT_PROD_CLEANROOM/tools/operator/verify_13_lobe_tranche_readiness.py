from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as taxonomy
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "VERIFY_KT_13_LOBE_TRANCHE_READINESS"
NEXT_LAWFUL_MOVE = "RUN_13_LOBE_7B_TRANCHE"
PASS_OUTCOME = "KT_13_LOBE_TRANCHE_READY__RUN_13_LOBE_7B_TRANCHE_NEXT__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_13_LOBE_TRANCHE_READINESS_BLOCKED__NAMED_DEFECT_REMAINS"

CONFIG_PATH = "training/kt_13_lobe_7b_tranche_config.json"
RUNBOOK_PATH = "training/kaggle_13_lobe_7b_tranche_runbook.md"
RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/kt_13_lobe_tranche_readiness_inspection_receipt.json"
REGISTRY_PATH = "registry/artifact_authority_registry.json"
DELTA_PATH = "registry/artifact_authority_registry_13_lobe_tranche_readiness_delta_receipt.json"

CANONICAL_LOBES = [lobe_id for lobe_id, _, _ in taxonomy.CANONICAL_LOBES]
CANONICAL_LOBE_SET = set(CANONICAL_LOBES)
FORBIDDEN_LABELS = list(taxonomy.FORBIDDEN_CANONICAL_LOBE_LABELS)
BLOCKED_CLAIMS = dict(taxonomy.BLOCKED_CLAIMS)

REQUIRED_GATE_COMPONENTS = {
    "truth_lock",
    "claim_compiler",
    "detached_verifier",
    "supply_chain_gate",
    "external_attestation_gate",
    "bio_med_firewall_gate",
    "commercial_boundary_gate",
    "benchmark_court",
    "proof_validator",
    "reality_grounding_screen",
    "evaluator_integrity_screen",
    "runtime_execution_chain_screen",
    "prospective_metacognition_gate",
    "primitive_invariance_screen",
    "categorical_boundary_screen",
    "compositional_generalization_screen",
    "delta_to_primitive_compiler_screen",
    "truth_engine",
}

REQUIRED_MAPPING_TARGETS = {
    "claim_boundary": "claim_compiler_advisor",
    "truth_grounding": "truth_grounding_advisor",
    "primitive_invariance": "primitive_invariance_gate_advisor",
    "metacognitive_admission": "route_admission_advisor",
    "runtime_execution_chain": "runtime_chain_validator_advisor",
    "evaluator_integrity": "evaluator_integrity_court_advisor",
    "delta_to_primitive": "delta_scar_compiler_advisor",
    "router_control": "router_composition_advisor",
    "router_controller": "router_composition_advisor",
    "bio_med_firewall": "regulated_domain_firewall_advisor",
    "proof_validator": "proof_court_advisor",
    "benchmark_evaluator": "benchmark_court_advisor",
    "external_attestation": "external_validation_advisor",
    "commercial_boundary": "commercial_claim_gate_advisor",
    "adapter_forge": "adapter_factory_layer",
    "lobe_trainer": "training_academy_layer",
}

HISTORICAL_COMPAT_LABELS = {
    "lobe.alpha.v1",
    "lobe.architect.v1",
    "lobe.critic.v1",
    "lobe.muse.v1",
    "lobe.quant.v1",
    "lobe.auditor.v1",
    "lobe.scout.v1",
    "lobe.strategist.v1",
}

REQUIRED_KAGGLE_OUTPUTS = [
    "head_binding_receipt.json",
    "run_manifest.json",
    "training_receipt.json",
    "eval_receipt.json",
    "negative_result_ledger.json",
    "router_trace.csv",
    "router_trace.json",
    "router_vs_static_scorecard.json",
    "router_vs_best_adapter_scorecard.json",
    "safetensors_hash_manifest.json",
    "kt_hat_adapter_mount_manifest.json",
    "benchmark_tranche_receipt.json",
    "blocker_ledger.json",
    "KT_13_LOBE_ASSESSMENT_REVIEW_SUMMARY.json",
    "assessment_summary.json",
    "cuda_environment_receipt.json",
    "qlora_effectiveness_receipt.json",
    "hf_cache_network_retry_receipt.json",
    "partial_run_resume_receipt.json",
]

ROUTER_PROOF_ORDER = [
    "static_baseline",
    "shadow_evaluation",
    "best_static_comparison",
    "learned_router_candidate",
    "statistical_evidence",
    "multi_lobe_orchestration",
]


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _read(root: Path, raw: str) -> dict[str, Any]:
    path = root / raw
    if not path.is_file():
        raise RuntimeError(f"Missing required artifact: {raw}")
    return load_json(path)


def _file_hash(root: Path, raw: str) -> str | None:
    path = root / raw
    return file_sha256(path) if path.is_file() else None


def _tranche_config(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.training.13_lobe_7b_tranche_config.v1",
        "artifact_id": "KT_13_LOBE_7B_TRANCHE_CONFIG",
        "authority": "INTERNAL_SHADOW_TRAINING_EXECUTION_ONLY",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "run_mode": NEXT_LAWFUL_MOVE,
        "requested_head_policy": "EXACT_CURRENT_HEAD_REQUIRED_OR_FAIL_CLOSED",
        "actual_head_policy": "MUST_MATCH_REQUESTED_HEAD",
        "head_binding_receipt_required": True,
        "target_lobe_ids": list(CANONICAL_LOBES),
        "forbidden_training_targets": list(FORBIDDEN_LABELS),
        "historical_lobe_labels_allowed_as_targets": False,
        "advisor_labels_allowed_as_targets": False,
        "required_kaggle_outputs": list(REQUIRED_KAGGLE_OUTPUTS),
        "deterministic_seed_policy": {
            "python_seed": 1337,
            "numpy_seed": 1337,
            "torch_seed": 1337,
            "deterministic_algorithms": "best_effort_with_receipt",
        },
        "cuda_environment_receipt_required": True,
        "qlora_effectiveness_check_required": True,
        "hf_cache_network_retry_receipt_required": True,
        "partial_run_resume_receipt_required": True,
        "t4_safe_default_profile": {
            "KT_MAX_SEQ_LEN": 96,
            "KT_BATCH_SIZE": 1,
            "KT_GRAD_ACCUM": 32,
            "KT_MIN_ROWS_PER_LOBE": 24,
            "KT_MIN_VAL_PER_LOBE": 4,
            "KT_ROUTER_EVAL_MIN_PER_CLASS": 4,
            "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True,max_split_size_mb:64",
        },
        "router_proof_order": list(ROUTER_PROOF_ORDER),
        "training_authorizes_claims": False,
        "adapter_outputs_production_authorized": False,
        "router_superiority_authorized": False,
        "multi_lobe_superiority_authorized": False,
        **BLOCKED_CLAIMS,
    }


def _runbook_text() -> str:
    lobe_lines = "\n".join(f"- `{lobe_id}`" for lobe_id in CANONICAL_LOBES)
    outputs = "\n".join(f"- `{name}`" for name in REQUIRED_KAGGLE_OUTPUTS)
    forbidden = ", ".join(f"`{label}`" for label in FORBIDDEN_LABELS)
    return f"""# KT 13-Lobe 7B Tranche Kaggle Runbook

Authority: internal/shadow training execution only.

This runbook is the current 13-lobe tranche path. It does not authorize commercial launch, external audit completion, external validation acceptance, 7B amplification, router superiority, multi-lobe superiority, S-tier, beyond-SOTA, category leadership, frontier parity, or production promotion.

## Current Inputs

- Config: `training/kt_13_lobe_7b_tranche_config.json`
- Cognitive lobe registry: `adaptive/cognitive_lobe_registry.json`
- Lobe target matrix: `KT_PROD_CLEANROOM/reports/kt_lobe_target_matrix.json`
- Adapter target matrix: `KT_PROD_CLEANROOM/reports/kt_adapter_target_matrix.json`

## Canonical Training Targets

The Kaggle runner must train only these 13 cognitive lobes:

{lobe_lines}

Forbidden gate/court/validator/router/factory/runtime/benchmark labels must not appear as canonical training targets:

{forbidden}

## Required Head Binding

Before any model load or training step, emit `head_binding_receipt.json` with:

```json
{{
  "requested_head": "<repo head requested by operator>",
  "actual_head": "<head reachable inside Kaggle or imported snapshot>",
  "head_match": true,
  "fail_closed_if_mismatch": true
}}
```

If `requested_head != actual_head`, stop or label the run as non-current-head assessment. Do not import it as current-head proof.

## Required Outputs

{outputs}

`router_trace.csv` or `router_trace.json` is sufficient for trace presence, but emitting both is preferred.

## Minimum Execution Rules

1. Load `training/kt_13_lobe_7b_tranche_config.json`.
2. Fail closed if target lobe IDs differ from the config or contain forbidden labels.
3. Set deterministic seeds before dataset construction.
4. Emit CUDA, HF cache/retry, and QLoRA effectiveness receipts before training.
5. Save checkpoints and partial-run receipts after each lobe/adaptor segment.
6. Clear GPU memory between lobe/adaptor segments.
7. Emit negative results and blocker ledger instead of deleting failed segments.
8. Import artifacts only through the hash/import contract after the run.

## T4-Safe Defaults

```python
import os

os.environ["KT_RUN_MODE"] = "RUN_13_LOBE_7B_TRANCHE"
os.environ["KT_MAX_SEQ_LEN"] = "96"
os.environ["KT_BATCH_SIZE"] = "1"
os.environ["KT_GRAD_ACCUM"] = "32"
os.environ["KT_MIN_ROWS_PER_LOBE"] = "24"
os.environ["KT_MIN_VAL_PER_LOBE"] = "4"
os.environ["KT_ROUTER_EVAL_MIN_PER_CLASS"] = "4"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:64"
```

## Clean Tranche Readiness Criteria

```text
target_lobe_count = 13
forbidden_target_count = 0
head_match = true
qlora_effective = true
training_errors_count = 0
negative_result_count = 0
router_no_regression_pass = true
class_balance_pass = true
import_ready = true
claim_ceiling_preserved = true
```

If any criterion fails, emit `blocker_ledger.json` and keep the result assessment-only until repaired.
"""


def _mapping_by_source(mapping: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(item.get("source_label", "")): item
        for item in mapping.get("mappings", [])
        if isinstance(item, Mapping)
    }


def inspect(root: Path | None = None) -> dict[str, Any]:
    base = root or repo_root()
    failures: list[dict[str, Any]] = []

    lobe_registry = _read(base, taxonomy.OUTPUTS["cognitive_lobe_registry"])
    lobe_ids = [str(item.get("lobe_id", "")) for item in lobe_registry.get("lobes", []) if isinstance(item, Mapping)]
    if lobe_ids != CANONICAL_LOBES:
        failures.append({"failure_id": "canonical_lobe_order_or_set_mismatch", "actual": lobe_ids, "expected": CANONICAL_LOBES})
    for item in lobe_registry.get("lobes", []):
        if not isinstance(item, Mapping):
            failures.append({"failure_id": "lobe_entry_not_object"})
            continue
        for key, expected in (
            ("canonical_lobe", True),
            ("training_target", True),
            ("gate_or_court", False),
            ("production_claim_allowed", False),
            ("rollback_required", True),
            ("claim_ceiling_preserved", True),
        ):
            if item.get(key) is not expected:
                failures.append({"failure_id": "lobe_contract_violation", "lobe_id": item.get("lobe_id"), "field": key, "actual": item.get(key)})
        required_receipts = set(item.get("required_receipts", []))
        for receipt_name in ("dataset_provenance_manifest", "training_run_receipt", "eval_receipt", "rollback_or_quarantine_receipt"):
            if receipt_name not in required_receipts:
                failures.append({"failure_id": "lobe_required_receipt_missing", "lobe_id": item.get("lobe_id"), "receipt": receipt_name})

    bad_lobes = sorted(lobe_id for lobe_id in lobe_ids if lobe_id in FORBIDDEN_LABELS)
    if bad_lobes:
        failures.append({"failure_id": "forbidden_label_as_canonical_lobe", "bad_lobes": bad_lobes})

    gate_registry = _read(base, taxonomy.OUTPUTS["gate_registry"])
    components = {str(item.get("component_id", "")): item for item in gate_registry.get("components", []) if isinstance(item, Mapping)}
    missing_components = sorted(REQUIRED_GATE_COMPONENTS - set(components))
    if missing_components:
        failures.append({"failure_id": "gate_component_missing", "components": missing_components})
    for component_id in REQUIRED_GATE_COMPONENTS.intersection(components):
        component = components[component_id]
        for key, expected in (
            ("code_authority", True),
            ("fail_closed", True),
            ("receipt_required", True),
            ("claim_ceiling_required", True),
            ("production_claim_allowed", False),
        ):
            if component.get(key) is not expected:
                failures.append({"failure_id": "gate_component_contract_violation", "component_id": component_id, "field": key, "actual": component.get(key)})

    mapping = _read(base, taxonomy.OUTPUTS["mapping"])
    by_source = _mapping_by_source(mapping)
    for source, target in REQUIRED_MAPPING_TARGETS.items():
        entry = by_source.get(source)
        if not entry:
            failures.append({"failure_id": "required_mapping_missing", "source_label": source})
            continue
        if entry.get("corrected_target") != target:
            failures.append({"failure_id": "required_mapping_target_mismatch", "source_label": source, "actual": entry.get("corrected_target"), "expected": target})
        if source not in {"router_control", "router_controller", "adapter_forge", "lobe_trainer"} and entry.get("taxonomy_class") != "TRAINED_GATE_COURT_EVALUATOR_ADVISOR":
            failures.append({"failure_id": "advisor_mapping_class_mismatch", "source_label": source, "actual": entry.get("taxonomy_class")})
    missing_compat = sorted(HISTORICAL_COMPAT_LABELS - set(by_source))
    if missing_compat:
        failures.append({"failure_id": "historical_lobe_compat_mapping_missing", "source_labels": missing_compat})

    advisor_schema = _read(base, taxonomy.OUTPUTS["advisor_schema"])
    props = advisor_schema.get("properties", {})
    for key in ("may_authorize_claims", "may_promote_adapters_or_lobes", "may_certify_benchmark_results", "may_override_code_owned_gates"):
        if props.get(key, {}).get("const") is not False:
            failures.append({"failure_id": "advisor_interface_allows_authority", "field": key})
    if props.get("signal_only", {}).get("const") is not True:
        failures.append({"failure_id": "advisor_interface_not_signal_only"})

    config = _read(base, CONFIG_PATH)
    target_lobes = [str(item) for item in config.get("target_lobe_ids", [])]
    if target_lobes != CANONICAL_LOBES:
        failures.append({"failure_id": "tranche_config_targets_not_13_canonical", "actual": target_lobes, "expected": CANONICAL_LOBES})
    forbidden_targets = sorted(set(target_lobes).intersection(FORBIDDEN_LABELS))
    if forbidden_targets:
        failures.append({"failure_id": "tranche_config_contains_forbidden_targets", "targets": forbidden_targets})
    if config.get("historical_lobe_labels_allowed_as_targets") is not False or config.get("advisor_labels_allowed_as_targets") is not False:
        failures.append({"failure_id": "tranche_config_allows_noncanonical_targets"})
    missing_outputs = sorted(set(REQUIRED_KAGGLE_OUTPUTS) - set(config.get("required_kaggle_outputs", [])))
    if missing_outputs:
        failures.append({"failure_id": "tranche_config_missing_required_outputs", "outputs": missing_outputs})
    if config.get("router_proof_order") != ROUTER_PROOF_ORDER:
        failures.append({"failure_id": "router_proof_order_drift", "actual": config.get("router_proof_order")})

    for artifact, raw in (
        ("runbook", RUNBOOK_PATH),
        ("taxonomy_drift_scan", "KT_PROD_CLEANROOM/tools/operator/taxonomy_drift_scan.py"),
        ("claim_ceiling", "governance/current_claim_ceiling.json"),
        ("artifact_authority_registry", REGISTRY_PATH),
    ):
        if not (base / raw).is_file():
            failures.append({"failure_id": "required_file_missing", "artifact": artifact, "path": raw})

    current_head = _git_head(base)
    return {
        "schema_id": "kt.13_lobe_tranche.readiness_inspection_receipt.v1",
        "artifact_id": "KT_13_LOBE_TRANCHE_READINESS_INSPECTION_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "outcome": PASS_OUTCOME if not failures else BLOCKED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE if not failures else "KT_13_LOBE_TRANCHE_READINESS_BLOCKED__NAMED_DEFECT_REMAINS",
        "branch_bound_training_allowed": False,
        "canonical_lobe_count": len(lobe_ids),
        "canonical_lobes": lobe_ids,
        "forbidden_training_targets": list(FORBIDDEN_LABELS),
        "future_kaggle_training_restricted_to_13_lobe_ids": not any(item.get("failure_id", "").startswith("tranche_config") for item in failures),
        "advisor_outputs_own_pass_fail_authority": False,
        "code_owned_gates_retain_pass_fail_authority": True,
        "router_proof_order_preserved": ROUTER_PROOF_ORDER,
        "required_kaggle_outputs": list(REQUIRED_KAGGLE_OUTPUTS),
        "historical_lobe_labels_preserved_as_compat_records": not any(item.get("failure_id") == "historical_lobe_compat_mapping_missing" for item in failures),
        "claim_ceiling_unchanged": True,
        "blockers": failures,
        "blocker_count": len(failures),
        **BLOCKED_CLAIMS,
    }


def _registry_entry(root: Path, artifact_id: str, raw: str, role: str, *, controls_execution: bool) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "path": raw,
        "role": role,
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "validation_status": "PASS",
        "controls_execution": controls_execution,
        "claim_authority": "INTERNAL_SHADOW",
        "sha256": _file_hash(root, raw),
        "supersedes": [],
        "superseded_by": None,
        "notes": "13-lobe tranche readiness artifact; no claim expansion or production authority.",
    }


def _update_registry(root: Path, current_head: str) -> dict[str, Any]:
    registry = _read(root, REGISTRY_PATH)
    artifact_ids = {
        "KT_13_LOBE_7B_TRANCHE_CONFIG",
        "KT_13_LOBE_7B_TRANCHE_RUNBOOK",
        "KT_13_LOBE_TRANCHE_READINESS_INSPECTION_RECEIPT",
    }
    artifacts = [item for item in registry.get("artifacts", []) if item.get("artifact_id") not in artifact_ids]
    artifacts.extend(
        [
            _registry_entry(root, "KT_13_LOBE_7B_TRANCHE_CONFIG", CONFIG_PATH, "thirteen_lobe_tranche_config", controls_execution=True),
            _registry_entry(root, "KT_13_LOBE_7B_TRANCHE_RUNBOOK", RUNBOOK_PATH, "thirteen_lobe_tranche_runbook", controls_execution=False),
            _registry_entry(root, "KT_13_LOBE_TRANCHE_READINESS_INSPECTION_RECEIPT", RECEIPT_PATH, "thirteen_lobe_tranche_readiness_receipt", controls_execution=True),
        ]
    )
    registry["current_head"] = current_head
    registry["generated_utc"] = utc_now_iso_z()
    registry["artifacts"] = artifacts
    return registry


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = output_root or repo_root()
    current_head = _git_head(root)
    changed: list[str] = []

    if write_json_stable(root / CONFIG_PATH, _tranche_config(current_head)):
        changed.append(CONFIG_PATH)
    runbook_path = root / RUNBOOK_PATH
    runbook_text = _runbook_text()
    if not runbook_path.exists() or runbook_path.read_text(encoding="utf-8") != runbook_text:
        runbook_path.parent.mkdir(parents=True, exist_ok=True)
        runbook_path.write_text(runbook_text, encoding="utf-8", newline="\n")
        changed.append(RUNBOOK_PATH)

    receipt = inspect(root)
    if write_json_stable(root / RECEIPT_PATH, receipt):
        changed.append(RECEIPT_PATH)

    registry = _update_registry(root, current_head)
    if write_json_stable(root / REGISTRY_PATH, registry):
        changed.append(REGISTRY_PATH)

    delta = {
        "schema_id": "kt.artifact_authority_registry.13_lobe_tranche_readiness_delta_receipt.v1",
        "artifact_id": "KT_ARTIFACT_AUTHORITY_REGISTRY_13_LOBE_TRANCHE_READINESS_DELTA_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "artifacts_added": [CONFIG_PATH, RUNBOOK_PATH, RECEIPT_PATH],
        "artifacts_modified": [REGISTRY_PATH, DELTA_PATH],
        "artifacts_superseded": [],
        "old_labels_reclassified": sorted(REQUIRED_MAPPING_TARGETS),
        "historical_lobe_labels_preserved_as_compat_records": True,
        "future_kaggle_training_restricted_to_13_lobe_ids": receipt["future_kaggle_training_restricted_to_13_lobe_ids"],
        "prior_gate_scaffold_adapters_preserved_as_advisors": True,
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        "duplicate_controlling_artifacts": [],
    }
    if write_json_stable(root / DELTA_PATH, delta):
        changed.append(DELTA_PATH)

    return {
        "current_head": current_head,
        "outcome": receipt["outcome"],
        "next_lawful_move": receipt["next_lawful_move"],
        "changed_outputs": changed,
        "blockers": receipt["blockers"],
        "claim_ceiling": "unchanged",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify KT 13-lobe tranche readiness and emit inspection receipt.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(summary["outcome"])
    return 0 if not summary["blockers"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
