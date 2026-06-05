from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_LOBES = [
    "strategic_synthesis_lobe",
    "audit_reasoning_lobe",
    "formal_proof_reasoning_lobe",
    "contradiction_paradox_lobe",
    "temporal_chronology_lobe",
    "cross_domain_patterncraft_lobe",
    "grounded_evidence_lobe",
    "regulated_domain_lobe",
    "commercial_operator_lobe",
    "execution_tool_lobe",
    "context_memory_compression_lobe",
    "learning_delta_lobe",
    "adversarial_red_assault_lobe",
]
FORBIDDEN_AS_LOBES = {
    "claim_boundary",
    "proof_validator",
    "truth_engine",
    "claim_compiler",
    "detached_verifier",
    "evaluator_integrity",
    "primitive_invariance",
    "metacognitive_admission",
    "runtime_execution_chain",
    "bio_med_firewall",
    "router_control",
}


def authority(**extra):
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    registry = json.loads((ROOT / "adaptive" / "cognitive_lobe_registry.json").read_text(encoding="utf-8"))
    entries = registry.get("lobes") or registry.get("entries") or registry
    if isinstance(entries, dict):
        lobe_ids = sorted(entries)
    else:
        lobe_ids = sorted(row.get("lobe_id") for row in entries)
    defects = []
    if sorted(CANONICAL_LOBES) != sorted(lobe_ids):
        defects.append({"canonical_lobe_mismatch": {"expected": sorted(CANONICAL_LOBES), "actual": lobe_ids}})
    forbidden_present = sorted(set(lobe_ids) & FORBIDDEN_AS_LOBES)
    if forbidden_present:
        defects.append({"forbidden_gate_labels_as_lobes": forbidden_present})
    status = "PASS" if not defects else "BLOCKED"
    write_json(
        ROOT / "reports" / "kt_13_lobe_authority_map_receipt.json",
        authority(
            schema_id="kt.13_lobe_authority_map_receipt.v1",
            status=status,
            canonical_lobe_count=len(lobe_ids),
            canonical_lobes=lobe_ids,
            training_target_authority="adaptive/cognitive_lobe_registry.json",
            gates_are_not_lobes=True,
            defects=defects,
        ),
    )
    write_json(
        ROOT / "reports" / "kt_lobe_gate_court_validator_separation_receipt.json",
        authority(
            schema_id="kt.lobe_gate_court_validator_separation_receipt.v1",
            status=status,
            lobes_think=True,
            router_selects=True,
            gates_courts_validators_judge=True,
            forbidden_labels_as_lobes=forbidden_present,
        ),
    )
    write_json(
        ROOT / "reports" / "kt_legacy_lobe_registry_supersession_map.json",
        authority(
            schema_id="kt.legacy_lobe_registry_supersession_map.v1",
            status="PASS",
            legacy_lobe_role_registry="historical_router_baseline_only",
            current_training_target_authority="adaptive/cognitive_lobe_registry.json",
            gate_court_validator_authority="governance/gate_court_validator_registry.json",
        ),
    )
    print(json.dumps({"status": status, "canonical_lobe_count": len(lobe_ids), "defects": defects}, indent=2))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
