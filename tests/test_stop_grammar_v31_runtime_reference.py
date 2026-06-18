from __future__ import annotations

import ast
import json
from pathlib import Path

from runtime.reference_court_v31 import adjudicate_reference_court_v31
from runtime.stop_fsm_v31 import StopGrammarV31RuntimeFSM


ROOT = Path(__file__).resolve().parents[1]


def cases() -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / "fixtures/stop_grammar_v31_adversarial_cases.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_reference_court_cases_match_fixture_expectations() -> None:
    for case in cases():
        finding = adjudicate_reference_court_v31(case["text"], ended_on_eos=case.get("eos", False))
        assert finding.semantic_boundary_type == case["expected"]
        assert finding.lawful is bool(case["lawful"])


def test_runtime_and_reference_agree_on_boundary_type() -> None:
    for case in cases():
        runtime = StopGrammarV31RuntimeFSM()
        decision = runtime.feed(case["text"], eos=case.get("eos", False), max_new_tokens=case.get("max_new_tokens", False))
        reference = adjudicate_reference_court_v31(
            case["text"],
            ended_on_eos=case.get("eos", False),
            ended_on_max_new_tokens=case.get("max_new_tokens", False),
        )
        assert decision.semantic_boundary_type.value == reference.semantic_boundary_type


def test_reference_court_does_not_import_runtime_fsm() -> None:
    tree = ast.parse((ROOT / "runtime/reference_court_v31.py").read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    assert not any("stop_fsm_v31" in item for item in imports)


def test_runtime_detector_is_incremental_zero_full_rescans() -> None:
    runtime = StopGrammarV31RuntimeFSM()
    runtime.feed("FINAL_")
    decision = runtime.feed("ANSWER: 42\n")
    assert decision.should_stop is True
    assert runtime.full_sequence_rescan_count == 0
    assert runtime.telemetry()["incremental_decode_count"] == 2


def test_second_marker_close_preserves_raw_and_cuts_visible() -> None:
    text = "FINAL_ANSWER: 7 oranges FINAL_ANSWER:"
    runtime = StopGrammarV31RuntimeFSM()
    decision = runtime.feed(text)
    assert decision.should_stop is True
    assert decision.semantic_boundary_type.value == "SECOND_MARKER_CLOSE"
    assert decision.visible_text == "FINAL_ANSWER: 7 oranges"
    assert runtime.text == text
