from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from tools.operator import g3_academy_pressure_repair_v1 as g3
from tools.operator import g31_causal_repair_superlane_v1 as g31
from tools.operator.titanium_common import file_sha256


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _stage_sources(tmp_path: Path) -> None:
    root = g31.repo_root()
    required = [
        "registry/artifact_authority_registry.json",
        g3.ARTIFACTS["g2_evidence_manifest"],
        g3.ARTIFACTS["g2_failure_map"],
        g3.ARTIFACTS["g2_route_regret_targets"],
        g3.ARTIFACTS["g3_metric_constitution"],
        g3.ARTIFACTS["human_anchor_manifest"],
        g3.ARTIFACTS["math_repair_corpus"],
        g3.ARTIFACTS["kt_hat_calibration_corpus"],
        g3.ARTIFACTS["packet_manifest"],
    ]
    for rel_path in required:
        source = root / rel_path
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _stage(tmp_path: Path) -> dict:
    _stage_sources(tmp_path)
    return g31.run(output_root=tmp_path)


def test_g31_builds_causal_autopsy_and_packet(tmp_path: Path) -> None:
    summary = _stage(tmp_path)
    receipt = _load(tmp_path / g31.ARTIFACTS["final_receipt"])
    trace_rows = _read_jsonl(tmp_path / g31.ARTIFACTS["per_sample_causal_trace"])
    packet_zip = tmp_path / g31.ARTIFACTS["packet_zip"]

    assert summary["outcome"] == g31.TARGET_OUTCOME
    assert summary["next_lawful_move"] == g31.NEXT_LAWFUL_MOVE
    assert summary["packet_sha256"] == file_sha256(packet_zip)
    assert receipt["g3_detailed_trace_gap_preserved"] is True
    assert receipt["causal_trace_rows"] == len(trace_rows)
    assert len(trace_rows) > 0
    assert all(row["failure_class"] != "unknown" for row in trace_rows)

    with zipfile.ZipFile(packet_zip) as zf:
        names = set(zf.namelist())
    assert {
        "KTG31_V1_CAUSAL_REPAIR_RUNNER.py",
        "KAGGLE_BOOTSTRAP_CELL.py",
        "g31_per_sample_causal_trace.jsonl",
        "g31_math_repair_corpus.jsonl",
        "g31_route_policy_training_pairs.jsonl",
        "g31_hat_calibration_corpus.jsonl",
    }.issubset(names)


def test_g31_math_route_hat_and_anchor_gates_pass_without_promotion(tmp_path: Path) -> None:
    _stage(tmp_path)
    math_receipt = _load(tmp_path / g31.ARTIFACTS["math_act_verifier_receipt"])
    route = _load(tmp_path / g31.ARTIFACTS["route_regret_closure_targets"])
    hat = _load(tmp_path / g31.ARTIFACTS["hat_salvage_suppression_matrix"])
    anchor = _load(tmp_path / g31.ARTIFACTS["human_anchor_quality_receipt"])
    adapter = _load(tmp_path / g31.ARTIFACTS["adapter_identity_scorecard"])

    assert math_receipt["math_act_verifier_pass"] is True
    assert route["simulation_pass"] is True
    assert route["empirical_router_superiority_claimed"] is False
    assert hat["non_math_no_regression_required_at_runtime"] is True
    assert anchor["human_anchor_ratio"] >= 0.20
    assert anchor["synthetic_only_repair_corpus"] is False
    assert adapter["promotion_allowed_from_build_mode"] is False
    assert adapter["runtime_child_adapter_hashes_required"] is True


def test_g31_packet_is_targeted_only_and_requires_runtime_evidence(tmp_path: Path) -> None:
    _stage(tmp_path)
    manifest = _load(tmp_path / g31.ARTIFACTS["packet_manifest"])
    runner = (tmp_path / g31.ARTIFACTS["packet_runner"]).read_text(encoding="utf-8")
    bootstrap = (tmp_path / g31.ARTIFACTS["packet_bootstrap"]).read_text(encoding="utf-8")

    assert manifest["trainable_targets"] == list(g31.G31_TARGETS)
    assert manifest["full_13_lobe_retrain_allowed"] is False
    assert manifest["claims_authorized"] == []
    assert "g3_1_math_act_adapter" in runner
    assert "g3_1_hat_policy_adapter" in runner
    assert "g3_1_route_regret_policy" in runner
    assert "AutoModelForCausalLM" in runner
    assert "get_peft_model" in runner
    assert "g31_ablation_scorecard.json" in runner
    assert "KT_PACKET_SHA256" in bootstrap
    assert "root in target.parents" in bootstrap
    assert "str(target).startswith" not in bootstrap


def test_g31_claim_ceiling_and_registry_delta_are_preserved(tmp_path: Path) -> None:
    _stage(tmp_path)
    delta = _load(tmp_path / g31.ARTIFACTS["artifact_delta"])
    registry = _load(tmp_path / g31.ARTIFACTS["artifact_registry"])
    ids = {row["artifact_id"] for row in registry["artifacts"]}

    assert "KT_G31_CAUSAL_REPAIR_RECEIPT" in ids
    assert "KTG31_CAUSAL_REPAIR_PACKET_V1" in ids
    assert delta["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    for key, expected in g31.BLOCKED_CLAIMS.items():
        assert delta[key] is expected


def test_g31_rejects_placeholder_pass_tokens(tmp_path: Path) -> None:
    _stage(tmp_path)
    no_placeholder = _load(tmp_path / g31.ARTIFACTS["no_placeholder_pass_receipt"])
    assert no_placeholder["no_placeholder_pass"] is True
    assert no_placeholder["findings"] == []
