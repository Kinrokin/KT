from __future__ import annotations

from tools.operator import highway_common as highway


def test_canonical_runtime_guard_preserves_safe_run_and_blocks_mutation(tmp_path):
    receipt = highway.canonical_runtime_guard(tmp_path, mutation_requested=True)
    assert receipt["safe_run_remains_lawful_entrypoint"] is True
    assert receipt["substitute_runtime_introduced"] is False
    assert receipt["canonical_mutation_allowed"] is False
    assert receipt["status"] == "BLOCKED_AUTHORITY_REQUIRED"
