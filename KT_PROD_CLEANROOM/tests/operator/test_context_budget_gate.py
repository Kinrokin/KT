from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.operator import context_budget_gate


def _copy_required_inputs(tmp_path: Path) -> None:
    root = context_budget_gate.repo_root()
    for raw in [
        *context_budget_gate.CURRENT_CONTEXT_INPUTS,
        *context_budget_gate.ARCHIVE_INDEX_INPUTS,
        ".agentignore",
    ]:
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def test_context_budget_gate_passes_current_context_first(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    receipt = context_budget_gate.evaluate(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["current_context_first"] is True
    assert receipt["archive_default_loaded"] is False
    assert receipt["delete_authorized"] is False
    assert receipt["current_inputs_missing"] == []


def test_context_budget_gate_blocks_missing_current_input(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    (tmp_path / "governance/current_claim_ceiling.json").unlink()
    receipt = context_budget_gate.evaluate(root=tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert "governance/current_claim_ceiling.json" in receipt["current_inputs_missing"]


def test_context_budget_gate_writes_receipt(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    receipt = context_budget_gate.evaluate(root=tmp_path)
    context_budget_gate.write_receipt(tmp_path, receipt)
    written = tmp_path / context_budget_gate.OUTPUT_RECEIPT
    assert written.is_file()
    assert json.loads(written.read_text(encoding="utf-8"))["status"] == "PASS"
