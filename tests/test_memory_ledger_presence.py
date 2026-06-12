from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_memory_entrypoint_files_exist() -> None:
    for rel in [
        "memory/CURRENT_CONTEXT.md",
        "memory/ACTIVE_CUTLINE.md",
        "memory/NEXT_LAWFUL_MOVE.md",
        "memory/ARTIFACT_INDEX.json",
        "memory/DECISION_LOG.jsonl",
        "memory/MISTAKE_LEDGER.md",
    ]:
        assert (ROOT / rel).exists()
