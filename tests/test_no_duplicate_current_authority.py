from __future__ import annotations

from pathlib import Path

from scripts.check_artifact_authority_registry import current_packet_errors, load_json


ROOT = Path(__file__).resolve().parents[1]


def test_no_duplicate_current_authority() -> None:
    registry = load_json(ROOT / "registry/artifact_authority_registry.json")
    assert current_packet_errors(registry["artifacts"]) == []
    current_packets = [
        artifact["path"]
        for artifact in registry["artifacts"]
        if artifact["primary_class"] == "CANONICAL_PACKET_CURRENT"
    ]
    # The BUD100/Pareto/KTCF/CFFIX packets have completed or superseded decisions.
    # PR-B's committed compile evidence explicitly denies execution authorization.
    # The invariant remains global uniqueness; an old BUD100 receipt is not a selector.
    assert current_packets == []
    decision = load_json(ROOT / "reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.json")
    assert decision["pr_b_execution_authorized"] is False
