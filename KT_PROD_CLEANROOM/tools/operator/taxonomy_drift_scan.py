from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as taxonomy
from tools.operator.titanium_common import load_json, repo_root


CANONICAL_LOBES = {lobe_id for lobe_id, _, _ in taxonomy.CANONICAL_LOBES}
FORBIDDEN_LABELS = set(taxonomy.FORBIDDEN_CANONICAL_LOBE_LABELS)


def _read(root: Path, raw: str) -> Mapping[str, Any]:
    path = root / raw
    if not path.is_file():
        raise RuntimeError(f"Missing taxonomy artifact: {raw}")
    obj = load_json(path)
    if not isinstance(obj, Mapping):
        raise RuntimeError(f"Taxonomy artifact is not an object: {raw}")
    return obj


def scan(*, root: Path | None = None) -> dict[str, Any]:
    base = root or repo_root()
    failures: list[dict[str, Any]] = []

    lobe_registry = _read(base, taxonomy.OUTPUTS["cognitive_lobe_registry"])
    lobes = lobe_registry.get("lobes", [])
    lobe_ids = [str(item.get("lobe_id", "")) for item in lobes if isinstance(item, Mapping)]
    if set(lobe_ids) != CANONICAL_LOBES or len(lobe_ids) != 13:
        failures.append(
            {
                "failure_id": "canonical_lobe_set_mismatch",
                "expected": sorted(CANONICAL_LOBES),
                "actual": sorted(lobe_ids),
            }
        )
    bad_lobes = sorted(lobe_id for lobe_id in lobe_ids if lobe_id in FORBIDDEN_LABELS or any(token in lobe_id for token in FORBIDDEN_LABELS))
    if bad_lobes:
        failures.append({"failure_id": "gate_court_validator_named_as_lobe", "bad_lobes": bad_lobes})
    for item in lobes:
        if not isinstance(item, Mapping):
            continue
        if item.get("training_target") is not True or item.get("canonical_lobe") is not True or item.get("gate_or_court") is not False:
            failures.append({"failure_id": "lobe_contract_violation", "lobe_id": item.get("lobe_id")})
        if item.get("claim_ceiling_preserved") is not True:
            failures.append({"failure_id": "lobe_claim_ceiling_not_preserved", "lobe_id": item.get("lobe_id")})

    gate_registry = _read(base, taxonomy.OUTPUTS["gate_registry"])
    for component in gate_registry.get("components", []):
        if not isinstance(component, Mapping):
            continue
        if component.get("code_authority") is not True or component.get("fail_closed") is not True:
            failures.append({"failure_id": "gate_not_code_authority_fail_closed", "component_id": component.get("component_id")})
        if component.get("production_claim_allowed") is not False:
            failures.append({"failure_id": "gate_production_claim_allowed", "component_id": component.get("component_id")})

    mapping = _read(base, taxonomy.OUTPUTS["mapping"])
    mapped_sources = {str(item.get("source_label", "")) for item in mapping.get("mappings", []) if isinstance(item, Mapping)}
    missing_forbidden = sorted(label for label in FORBIDDEN_LABELS if label not in mapped_sources)
    if missing_forbidden:
        failures.append({"failure_id": "forbidden_label_missing_from_mapping", "labels": missing_forbidden})
    for item in mapping.get("mappings", []):
        if not isinstance(item, Mapping):
            continue
        if item.get("taxonomy_class") == "TRAINED_GATE_COURT_EVALUATOR_ADVISOR":
            if item.get("canonical_lobe") is not False or item.get("advisor_only") is not True:
                failures.append({"failure_id": "advisor_mapping_not_advisory_only", "source_label": item.get("source_label")})

    lobe_target = _read(base, taxonomy.OUTPUTS["lobe_target_matrix"])
    target_lobes = [str(item.get("lobe_id", "")) for item in lobe_target.get("lobes", []) if isinstance(item, Mapping)]
    if set(target_lobes) != CANONICAL_LOBES or len(target_lobes) != 13:
        failures.append({"failure_id": "future_kaggle_lobe_targets_not_13_canonical", "actual": sorted(target_lobes)})

    adapter_target = _read(base, taxonomy.OUTPUTS["adapter_target_matrix"])
    bad_parent_lobes = sorted(
        str(item.get("parent_lobe", ""))
        for item in adapter_target.get("adapters", [])
        if isinstance(item, Mapping) and str(item.get("parent_lobe", "")) not in CANONICAL_LOBES
    )
    if bad_parent_lobes:
        failures.append({"failure_id": "adapter_parent_lobe_not_canonical", "bad_parent_lobes": bad_parent_lobes})

    advisor_schema = _read(base, taxonomy.OUTPUTS["advisor_schema"])
    props = advisor_schema.get("properties", {})
    if props.get("may_authorize_claims", {}).get("const") is not False:
        failures.append({"failure_id": "advisor_may_authorize_claims"})
    if props.get("may_promote_adapters_or_lobes", {}).get("const") is not False:
        failures.append({"failure_id": "advisor_may_promote"})
    if props.get("may_certify_benchmark_results", {}).get("const") is not False:
        failures.append({"failure_id": "advisor_may_certify_benchmark"})
    if props.get("may_override_code_owned_gates", {}).get("const") is not False:
        failures.append({"failure_id": "advisor_may_override_code_gate"})

    receipt = _read(base, taxonomy.OUTPUTS["reconciliation_receipt"])
    for key, expected in taxonomy.BLOCKED_CLAIMS.items():
        if receipt.get(key) is not expected:
            failures.append({"failure_id": "claim_ceiling_drift", "field": key, "actual": receipt.get(key), "expected": expected})

    return {
        "schema_id": "kt.operator.taxonomy_drift_scan.receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "failure_count": len(failures),
        "failures": failures,
        "canonical_lobe_count": len(lobe_ids),
        "forbidden_label_count": len(FORBIDDEN_LABELS),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan KT taxonomy artifacts for lobe/gate/court drift.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    receipt = scan()
    if args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(receipt["status"])
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
