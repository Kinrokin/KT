from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from tools.operator import g3_academy_pressure_repair_v1 as g3
from tools.operator import g3_targeted_runtime_packet_v2 as v2
from tools.operator.titanium_common import file_sha256


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _stage_sources(tmp_path: Path) -> None:
    root = v2.repo_root()
    for rel_path in [
        "registry/artifact_authority_registry.json",
        g3.ARTIFACTS["g2_evidence_manifest"],
        g3.ARTIFACTS["g2_failure_map"],
        g3.ARTIFACTS["g2_route_regret_targets"],
        g3.ARTIFACTS["human_anchor_manifest"],
        g3.ARTIFACTS["g3_metric_constitution"],
        g3.ARTIFACTS["formal_math_repair_plan"],
        g3.ARTIFACTS["math_repair_corpus"],
        g3.ARTIFACTS["kt_hat_calibration_corpus"],
    ]:
        source = root / rel_path
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _stage(tmp_path: Path) -> dict:
    _stage_sources(tmp_path)
    return v2.run(output_root=tmp_path)


def test_g3_v2_emits_executable_runtime_packet_not_intent_packet(tmp_path: Path) -> None:
    summary = _stage(tmp_path)
    manifest = _load(tmp_path / v2.ARTIFACTS["packet_manifest"])
    receipt = _load(tmp_path / v2.ARTIFACTS["runtime_packet_receipt"])
    packet_zip = tmp_path / v2.ARTIFACTS["packet_zip"]

    assert summary["outcome"] == v2.TARGET_OUTCOME
    assert summary["next_lawful_move"] == v2.NEXT_LAWFUL_MOVE
    assert summary["packet_sha256"] == file_sha256(packet_zip)
    assert manifest["runner_kind"] == "EXECUTABLE_TARGETED_PEFT_RUNTIME"
    assert manifest["runtime_intent_only"] is False
    assert manifest["requires_runtime_training"] is True
    assert manifest["requires_hf_final_only_upload_for_clean_pass"] is True
    assert receipt["runtime_training_required"] is True
    assert receipt["runtime_intent_only"] is False

    with zipfile.ZipFile(packet_zip) as zf:
        names = set(zf.namelist())
    assert {
        "KTG3_TARGETED_REPAIR_V2_RUNNER.py",
        "KAGGLE_BOOTSTRAP_CELL.py",
        "G2_FAILURE_MAP.json",
        "G2_ROUTE_REGRET_TARGETS.json",
        "G3_MATH_REPAIR_CORPUS.jsonl",
        "G3_KT_HAT_CALIBRATION_CORPUS.jsonl",
    }.issubset(names)


def test_g3_v2_runner_contains_real_training_and_required_receipts(tmp_path: Path) -> None:
    _stage(tmp_path)
    runner = (tmp_path / v2.ARTIFACTS["packet_runner"]).read_text(encoding="utf-8")

    assert "AutoModelForCausalLM" in runner
    assert "LoraConfig" in runner
    assert "get_peft_model" in runner
    assert "model.save_pretrained" in runner
    assert "adapter_model.safetensors" not in runner  # hashes are discovered, not assumed
    for required in v2.RUNTIME_REQUIRED_OUTPUTS:
        assert required in runner
    assert "*_ASSESSMENT_ONLY.zip" not in runner
    assert "ASSESSMENT_ONLY.zip" in runner
    assert "runtime_intent" not in runner
    assert "PENDING_EXECUTION" not in runner
    assert "PLACEHOLDER" not in runner


def test_g3_v2_bootstrap_uses_external_packet_hash_and_safe_extract(tmp_path: Path) -> None:
    _stage(tmp_path)
    bootstrap = (tmp_path / v2.ARTIFACTS["packet_bootstrap"]).read_text(encoding="utf-8")

    assert "KT_PACKET_SHA256" in bootstrap
    assert "if not expected:" in bootstrap
    assert "Multiple candidate packets found" in bootstrap
    assert "root in target.parents" in bootstrap
    assert "str(target).startswith" not in bootstrap
    assert "pip" in bootstrap
    assert "bitsandbytes" in bootstrap


def test_g3_v2_registry_delta_supersedes_intent_packet_without_claim_expansion(tmp_path: Path) -> None:
    _stage(tmp_path)
    registry = _load(tmp_path / v2.ARTIFACTS["artifact_registry"])
    delta = _load(tmp_path / v2.ARTIFACTS["artifact_delta"])
    by_id = {row["artifact_id"]: row for row in registry["artifacts"]}

    assert "KTG3_TARGETED_RUNTIME_PACKET_V2" in by_id
    assert "KTG3_TARGETED_RUNTIME_PACKET_V2_RECEIPT" in by_id
    assert delta["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    assert "KTG3_TARGETED_RUN_PACKET" in delta["artifacts_superseded"]
    for key, expected in g3.BLOCKED_CLAIMS.items():
        assert delta[key] is expected


def test_g3_v2_packet_requires_hf_upload_for_clean_runtime_pass(tmp_path: Path) -> None:
    _stage(tmp_path)
    manifest = _load(tmp_path / v2.ARTIFACTS["packet_manifest"])
    runner = (tmp_path / v2.ARTIFACTS["packet_runner"]).read_text(encoding="utf-8")

    assert manifest["requires_hf_final_only_upload_for_clean_pass"] is True
    assert "KT_REQUIRE_HF_UPLOAD" in runner
    assert "HF_TOKEN_MISSING" in runner
    assert "KT_HF_REPO_ID_MISSING" in runner
    assert "upload_pass" in runner
