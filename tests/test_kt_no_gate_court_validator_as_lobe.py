from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_no_gate_court_validator_label_is_canonical_lobe() -> None:
    registry = json.loads((ROOT / "adaptive" / "cognitive_lobe_registry.json").read_text(encoding="utf-8"))
    entries = registry.get("lobes") or registry.get("entries") or registry
    lobe_ids = set(entries if isinstance(entries, dict) else row["lobe_id"] for row in entries)
    forbidden = {
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
    assert not (lobe_ids & forbidden)
