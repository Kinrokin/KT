from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_oracle_academy_reprolock_packet as builder


ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return json.loads((ROOT / "admission" / "v17_7_4_realbench_row_manifest.json").read_text(encoding="utf-8-sig"))


def _prior_rows() -> dict[str, dict]:
    rows = {}
    for line in (ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        rows[row["sample_id"]] = row
    return rows


def test_prior_realbench_prompt_renderer_matches_archived_hashes_50_for_50() -> None:
    prior_rows = _prior_rows()
    arm = {"prompt_template_id": "math_act", "legacy_prompt_template_id": "math_act", "reproduction_mode": core.TRUE_KNOWN_GOOD_BYTE_REPRO}
    matches = 0
    for row in _manifest()["rows"][:50]:
        prompt = core.prior_realbench_materialize_prompt(row, arm)
        if core.sha256_text(prompt) == prior_rows[row["sample_id"]]["prior_prompt_hash"]:
            matches += 1
    assert matches == 50


def test_true_known_good_byte_repro_prompt_forbids_new_scaffolds() -> None:
    row = _manifest()["rows"][0]
    arm = {
        "arm_id": core.REPROLOCK_ARM_ID,
        "prompt_template_id": "math_act",
        "legacy_prompt_template_id": "math_act",
        "reproduction_mode": core.TRUE_KNOWN_GOOD_BYTE_REPRO,
    }
    prompt = core.materialize_prompt(row, arm)
    assert "Decompose the math act briefly" in prompt
    assert "Question:" in prompt
    assert "Answer format:" in prompt
    assert "Final:" in prompt
    assert "Compact mode:" not in prompt
    assert "Mode rule:" not in prompt
    assert "KT-hat" not in prompt
    assert "oracle shadow" not in prompt.lower()


def test_reprolock_stage0_passes_with_archived_prior_prompt_hashes(tmp_path, monkeypatch) -> None:
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    prior_path = inputs / "prior_realbench_math_act_prompt_manifest.jsonl"
    prior_path.write_text((ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    config = builder.reprolock_config()
    config["base_model_repo"] = "__KT_LOCAL_TEST_BACKEND__"
    config["load_in_4bit"] = False
    config["real_arm_authority_requested"] = False
    config["arms"][0]["model_repo_or_base"] = "__KT_LOCAL_TEST_BACKEND__"
    manifest = _manifest()
    manifest["rows"] = manifest["rows"][:2]
    manifest["row_count"] = 2
    monkeypatch.setenv("KT_REPROLOCK_LOAD_TOKENIZER", "0")
    receipt = core.run_reprolock_stage0(runtime_root, tmp_path / "out", manifest, config)
    assert receipt["status"] == "PASS"
    assert receipt["generation_allowed"] is True
    assert (tmp_path / "out" / "v17_7_4_prompt_hash_reproduction_matrix.jsonl").exists()


def test_reprolock_stage0_blocks_on_prompt_hash_drift(tmp_path, monkeypatch) -> None:
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    prior_rows = []
    for line in (ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["sample_id"] == "gsm8k:test:0":
            row["prior_prompt_hash"] = "0" * 64
        prior_rows.append(row)
    (inputs / "prior_realbench_math_act_prompt_manifest.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in prior_rows),
        encoding="utf-8",
    )
    config = builder.reprolock_config()
    config["base_model_repo"] = "__KT_LOCAL_TEST_BACKEND__"
    config["load_in_4bit"] = False
    config["real_arm_authority_requested"] = False
    config["arms"][0]["model_repo_or_base"] = "__KT_LOCAL_TEST_BACKEND__"
    manifest = _manifest()
    manifest["rows"] = manifest["rows"][:1]
    manifest["row_count"] = 1
    monkeypatch.setenv("KT_REPROLOCK_LOAD_TOKENIZER", "0")
    with pytest.raises(RuntimeError, match="KT_BLOCKED__PROMPT_HASH_REPRODUCTION_FAILED"):
        core.run_reprolock_stage0(runtime_root, tmp_path / "out", manifest, config)


def test_reprolock_config_and_packet_contract_if_generated() -> None:
    config = builder.reprolock_config()
    assert config["measurement_mode"] == core.REPROLOCK_MODE
    assert config["required_arm_ids"] == [core.REPROLOCK_ARM_ID]
    assert len(config["arms"]) == 1
    arm = config["arms"][0]
    assert arm["arm_id"] == core.REPROLOCK_ARM_ID
    assert arm["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arm["score_from_visible_answer"] is False
    assert arm["finalizer_intervention_disabled"] is True
    assert arm["kt_hat_scaffold_disabled"] is True
    assert arm["route_admission_disabled"] is True
    assert core.validate_arm_model_config(config) == []

    packet = ROOT / "packets" / builder.PACKET_NAME
    if not packet.exists():
        return
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        run_manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        packet_config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
    assert "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl" in names
    assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
    assert run_manifest["run_mode"] == builder.NEXT_LAWFUL_MOVE
    assert run_manifest["measurement_mode"] == core.REPROLOCK_MODE
    assert packet_config["required_arm_ids"] == [core.REPROLOCK_ARM_ID]
