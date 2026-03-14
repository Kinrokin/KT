from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.paradox_verification_compile import (  # noqa: E402
    REQUIRED_INVARIANT_IDS,
    build_step10_outputs,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_step10_outputs_cover_required_invariants_and_ttl_schedule() -> None:
    root = repo_root()
    outputs = build_step10_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    invariants = outputs["kt_paradox_invariants"]["invariants"]
    assert [row["invariant_id"] for row in invariants] == REQUIRED_INVARIANT_IDS
    assert outputs["kt_paradox_stress_results"]["stress_verdict"] == "PASS"
    assert outputs["kt_paradox_counterexamples"]["summary"]["unresolved_count"] == 0
    assert outputs["kt_paradox_claim_matrix"]["current_status"] == "evidenced"

    scheduler = outputs["kt_proof_obligation_scheduler"]
    assert scheduler["scheduler_basis"]["ttl_duration"] == "P7D"
    assert scheduler["summary"]["scheduled_count"] == 4
    assert all(row["current_status"] == "ACTIVE_WITH_TTL" for row in scheduler["scheduled_obligations"])

    model_text = outputs["kt_paradox_models_tla"]
    for invariant_id in (
        "NoInfiniteContradictionLoop",
        "NoIndefiniteHoldWithoutTTL",
        "NoGovernanceBypassUnderParadoxLoad",
        "NoSilentFlatteningToTrivialAnswers",
        "NoUntrackedDeltaGenerationDuringResolution",
    ):
        assert invariant_id in model_text


def test_step10_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first = build_step10_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    second = build_step10_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert first["kt_paradox_models_tla"] == second["kt_paradox_models_tla"]
    for key in first:
        if key == "kt_paradox_models_tla":
            continue
        assert semantically_equal_json(first[key], second[key]), key
