from __future__ import annotations

import ast
import json
import zipfile

from ktstop300_common import (
    ADMISSION,
    REPORTS,
    ROOT,
    STOP300_DATASET,
    STOP300_PACKET,
    STOP300_RUN_MODE,
    authority_payload,
    read_json,
    rel,
    sha256_file,
    write_json,
)


REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/stop_fsm_v31.py",
    "runtime/output_delivery.py",
    "runtime/reference_court_v31.py",
    "runtime/environment_preflight.py",
    "runtime/effective_config_receipt.py",
    "runtime/timing_protocol.py",
    "runtime/resume_ledger.py",
    "runtime/ktstop300_config.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop300_v1.txt",
}


def imports_from_source(source: str) -> list[str]:
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return imports


def main() -> int:
    errors: list[str] = []
    if not STOP300_PACKET.exists():
        raise SystemExit("missing STOP300 packet")
    with zipfile.ZipFile(STOP300_PACKET) as zf:
        members = set(zf.namelist())
        missing = sorted(REQUIRED_MEMBERS - members)
        if missing:
            errors.append(f"missing members: {missing}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_config.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        reference = zf.read("runtime/reference_court_v31.py").decode("utf-8-sig")
        requirements = zf.read("requirements.txt").decode("utf-8-sig")

    if manifest.get("run_mode") != STOP300_RUN_MODE:
        errors.append("run_mode mismatch")
    if manifest.get("kaggle_dataset_name") != STOP300_DATASET:
        errors.append("dataset mismatch")
    if manifest.get("natural_row_count") != 300:
        errors.append("natural row count mismatch")
    if len(config.get("natural_rows", [])) != 300:
        errors.append("config natural rows mismatch")
    if len(config.get("timing_panel_rows", [])) != 60:
        errors.append("timing panel rows mismatch")
    if any("expected_answer" in row for row in config.get("natural_rows", [])):
        errors.append("expected answers must not be embedded")
    for key in [
        "shadow_runtime_authority",
        "runtime_authority",
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        if manifest.get(key):
            errors.append(f"{key} must remain false")
    if "bitsandbytes==0.49.2" not in requirements:
        errors.append("bitsandbytes pin missing")
    if "BitsAndBytesConfig" in runner:
        errors.append("runner must not introduce runtime BitsAndBytesConfig")
    if "full_sequence_rescan_count" not in runner:
        errors.append("runner must emit detector rescan telemetry")
    if any("stop_fsm_v31" in item for item in imports_from_source(reference)):
        errors.append("reference court imports runtime fsm")

    selected = read_json(ADMISSION / "stop300_stratified_hash_selected_manifest.json")
    timing = read_json(ADMISSION / "stop300_timing_panel_manifest.json")
    if selected["stratum_counts"] != {"EASY": 100, "HARD": 100, "MEDIUM": 100}:
        errors.append("natural stratum balance failed")
    if timing["stratum_counts"] != {"EASY": 20, "HARD": 20, "MEDIUM": 20}:
        errors.append("timing stratum balance failed")
    risk = read_json(ADMISSION / "runtime_stop_risk_tolerance_contract.json")
    if risk["observed_damage_tolerance"] != 0:
        errors.append("damage tolerance must be zero")
    replay = read_json(REPORTS / "historical_first_vs_last_answer_counterfactual_replay.json")
    if replay["classification_counts_exact_protocol"].get("FIRST_WRONG_LATER_CORRECT", 0) != 0:
        errors.append("first-wrong-later-correct exact protocol nonzero")
    grammar = read_json(REPORTS / "stop_grammar_v31_status.json")
    if grammar["status"] != "PASS_STOP_GRAMMAR_V31_READY":
        errors.append("grammar v31 not ready")

    receipt = {
        "schema_id": "kt.stop300.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(STOP300_PACKET),
        "packet_sha256": sha256_file(STOP300_PACKET),
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "errors": errors,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("STOP300 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
