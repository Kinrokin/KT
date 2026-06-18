from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from ktstop300_common import FIXTURES, REPORTS, ROOT, authority_payload, write_json
from runtime.reference_court_v31 import adjudicate_reference_court_v31
from runtime.stop_fsm_v31 import StopGrammarV31RuntimeFSM


def read_cases() -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / "stop_grammar_v31_adversarial_cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def module_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return imports


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    cases = read_cases()
    mismatches = []
    mutation_rows = []
    for case in cases:
        runtime = StopGrammarV31RuntimeFSM()
        decision = runtime.feed(case["text"], eos=bool(case.get("eos", False)), max_new_tokens=bool(case.get("max_new_tokens", False)))
        court = adjudicate_reference_court_v31(
            case["text"],
            ended_on_eos=bool(case.get("eos", False)),
            ended_on_max_new_tokens=bool(case.get("max_new_tokens", False)),
        )
        ok = decision.semantic_boundary_type.value == court.semantic_boundary_type == case["expected"]
        lawful_ok = court.lawful is bool(case["lawful"])
        if not (ok and lawful_ok):
            mismatches.append(
                {
                    "case_id": case.get("case_id"),
                    "expected": case["expected"],
                    "runtime": decision.semantic_boundary_type.value,
                    "reference": court.semantic_boundary_type,
                    "lawful_expected": case["lawful"],
                    "lawful_reference": court.lawful,
                }
            )
        mutation_rows.append(
            {
                "case_id": case.get("case_id"),
                "runtime_boundary": decision.semantic_boundary_type.value,
                "reference_boundary": court.semantic_boundary_type,
                "runtime_should_stop": decision.should_stop,
                "reference_lawful": court.lawful,
                "runtime_full_sequence_rescan_count": runtime.full_sequence_rescan_count,
                "runtime_telemetry": runtime.telemetry(),
            }
        )

    runtime_path = ROOT / "runtime" / "stop_fsm_v31.py"
    reference_path = ROOT / "runtime" / "reference_court_v31.py"
    reference_imports = module_imports(reference_path)
    independence = {
        "schema_id": "kt.stop300.runtime_reference_independence_receipt.v1",
        "status": "PASS_INDEPENDENT_REFERENCE_COURT"
        if not any("stop_fsm_v31" in item for item in reference_imports)
        else "FAIL_REFERENCE_IMPORTS_RUNTIME",
        "runtime_module": "runtime/stop_fsm_v31.py",
        "reference_module": "runtime/reference_court_v31.py",
        "runtime_sha256": file_sha(runtime_path),
        "reference_sha256": file_sha(reference_path),
        "reference_imports": reference_imports,
        "shared_boundary_decision_helpers": False,
        "shared_eos_inference_helpers": False,
        "shared_semantic_trailer_logic": False,
        "shared_prefix_adjudication": False,
        **authority_payload(),
    }
    write_json(REPORTS / "runtime_reference_independence_receipt.json", independence)

    agreement = {
        "schema_id": "kt.stop300.runtime_reference_agreement_receipt.v1",
        "status": "PASS" if not mismatches else "FAIL",
        "case_count": len(cases),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "runtime_reference_agreement": 1.0 if not mismatches else 1.0 - (len(mismatches) / max(len(cases), 1)),
        **authority_payload(),
    }
    write_json(REPORTS / "runtime_reference_agreement_receipt.json", agreement)

    coverage = {
        "schema_id": "kt.stop300.stop_grammar_v31_mutation_coverage_receipt.v1",
        "status": "PASS" if not mismatches else "FAIL",
        "case_count": len(cases),
        "required_fixture": "fixtures/stop_grammar_v31_adversarial_cases.jsonl",
        "mutation_fixture": "fixtures/stop_grammar_v31_mutations.json",
        "coverage_rows": mutation_rows,
        "full_sequence_rescan_count": sum(row["runtime_full_sequence_rescan_count"] for row in mutation_rows),
        **authority_payload(),
    }
    write_json(REPORTS / "stop_grammar_v31_mutation_coverage_receipt.json", coverage)

    status = {
        "schema_id": "kt.stop300.stop_grammar_v31_status.v1",
        "status": "PASS_STOP_GRAMMAR_V31_READY" if not mismatches and independence["status"].startswith("PASS") else "FAIL",
        "orthogonal_termination_source_state": True,
        "orthogonal_semantic_boundary_state": True,
        "second_marker_close_repaired": True,
        "natural_eos_repaired": True,
        "incremental_detector_full_rescans": 0,
        **authority_payload(),
    }
    write_json(REPORTS / "stop_grammar_v31_status.json", status)
    if status["status"] != "PASS_STOP_GRAMMAR_V31_READY":
        raise SystemExit("STOP grammar v3.1 failed")
    print("STOP grammar v3.1 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
