from __future__ import annotations

import json
import subprocess
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def test_ktstop_receipts_are_evidence_bound_after_runner() -> None:
    subprocess.run(["python", "scripts/run_stop_after_final_answer_probe.py"], check=True)

    truth = load("reports/ktstop_truth_pin.json")
    hash_lock = load("reports/ktstop_cffix_hash_lock_receipt.json")
    selection = load("reports/ktstop_10row_selection.json")
    blocker = load("reports/stop_after_final_answer_probe_blocker.json")

    assert truth["claim_ceiling_status"] == "PRESERVED"
    assert hash_lock["patch_authority_from_old_cffix"] is False
    assert selection["status"] == "PASS"
    assert selection["row_count"] == 10
    assert len(selection["rows"]) == 10
    assert all(row["gold_prompt_leakage_free"] is True for row in selection["rows"])
    assert all("expected_answer_hash" in row for row in selection["rows"])
    assert all("expected_answer" not in row for row in selection["rows"])
    assert blocker["status"] == "BLOCKED_LOCAL_MODEL_RUNTIME_UNAVAILABLE__STOPSEQ_PROBE_HARNESS_READY"
    assert blocker["prompt_delta_committed"] is False
    assert blocker["training_authority"] is False
    assert blocker["production_prompt_mutation_authority"] is False
