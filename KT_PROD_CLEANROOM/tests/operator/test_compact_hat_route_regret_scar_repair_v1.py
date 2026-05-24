from __future__ import annotations

import json
import shutil
import zipfile
from hashlib import sha256
from pathlib import Path

from tools.operator import compact_hat_route_regret_scar_repair_v1 as repair


def _copy_inputs(tmp_path: Path) -> None:
    root = repair.repo_root()
    for raw in ["registry/artifact_authority_registry.json"]:
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / raw, target)


def _stage(tmp_path: Path) -> dict:
    _copy_inputs(tmp_path)
    return repair.run(output_root=tmp_path)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_compact_hat_route_regret_scar_repair_emits_ready_receipts(tmp_path: Path) -> None:
    summary = _stage(tmp_path)
    receipt = _load(tmp_path / repair.ARTIFACTS["repair_readiness_receipt"])
    inspection = _load(tmp_path / repair.ARTIFACTS["inspection_receipt"])

    assert summary["outcome"] == repair.TARGET_OUTCOME
    assert summary["next_lawful_move"] == repair.NEXT_LAWFUL_MOVE
    assert receipt["selected_outcome"] == repair.TARGET_OUTCOME
    assert receipt["expanded_benchmark_packet_ready"] is True
    assert inspection["repo_first"] is True
    assert inspection["kaggle_first"] is False
    assert receipt["claim_ceiling_preserved"] is True


def test_kt_hat_modes_include_bench_answer_only_and_token_budgets(tmp_path: Path) -> None:
    _stage(tmp_path)
    contract = _load(tmp_path / repair.ARTIFACTS["kt_hat_mode_contract"])
    bench = _load(tmp_path / repair.ARTIFACTS["kt_hat_bench_policy"])

    assert set(contract["modes"]) == {"compact", "bench", "operator", "high_risk", "math", "audit"}
    assert bench["mode"] == "bench"
    assert bench["answer_style"] == "answer_only"
    assert bench["max_overhead_tokens"] <= 96
    assert bench["benchmark_narrative_suppressed"] is True
    assert bench["claim_ceiling_preserved"] is True


def test_math_answer_extraction_handles_common_final_answer_formats() -> None:
    assert repair.normalize_math_answer("We get \\boxed{42}.") == "42"
    assert repair.normalize_math_answer("#### 1,234") == "1234"
    assert repair.normalize_math_answer("Final answer: 3/4") == "0.75"
    score = repair.score_math_answers(
        [
            {"sample_id": "a", "expected": "#### 42", "actual": "\\boxed{42}"},
            {"sample_id": "b", "expected": "answer: 7", "actual": "answer: 8"},
        ]
    )
    assert score["accuracy"] == 0.5


def test_formal_math_repair_targets_only_canonical_lobes(tmp_path: Path) -> None:
    _stage(tmp_path)
    config = _load(tmp_path / repair.ARTIFACTS["formal_math_tranche_config"])

    assert set(config["target_lobe_ids"]).issubset(set(repair.CANONICAL_LOBES))
    assert "claim_boundary" not in config["target_lobe_ids"]
    assert config["numeric_answer_extraction_required"] is True
    assert config["training_authorizes_claims"] is False


def test_route_regret_matrix_computes_best_route_gap_and_overroute() -> None:
    matrix = repair.build_route_regret_matrix(
        [
            {
                "sample_id": "s1",
                "selected_route": "heavy",
                "route_scores": {"base": 0.9, "heavy": 0.8},
                "token_count": 100,
                "routed_to_heavy": True,
            },
            {
                "sample_id": "s2",
                "selected_route": "compact",
                "route_scores": {"base": 0.4, "compact": 0.7},
                "token_count": 50,
            },
        ]
    )

    assert matrix["sample_count"] == 2
    assert matrix["rows"][0]["best_route"] == "base"
    assert matrix["rows"][0]["route_regret"] > 0
    assert matrix["rows"][0]["overroute"] is True
    assert abs(matrix["rows"][1]["verified_work_per_token"] - 0.014) < 1e-12


def test_router_objective_is_verified_work_not_label_fit(tmp_path: Path) -> None:
    _stage(tmp_path)
    scorecard_schema = _load(tmp_path / repair.ARTIFACTS["route_regret_scorecard_schema"])
    assert scorecard_schema["properties"]["router_optimizes_verified_work_not_label_fit"]["const"] is True


def test_scar_delta_distinctness_requires_hash_distinctness_and_failure_mapping() -> None:
    good = repair.verify_delta_distinctness(
        failure_rows=[{"failure_id": "f1"}, {"failure_id": "f2"}],
        delta_rows=[{"source_failure_id": "f1"}, {"source_failure_id": "f2"}],
        parent_adapter_hash="aaa",
        delta_adapter_hash="bbb",
    )
    bad = repair.verify_delta_distinctness(
        failure_rows=[{"failure_id": "f1"}],
        delta_rows=[{"source_failure_id": "unknown"}],
        parent_adapter_hash="same",
        delta_adapter_hash="same",
    )

    assert good["scar_learning_claim_allowed"] is True
    assert bad["scar_learning_claim_allowed"] is False
    assert bad["delta_adapter_hash_distinct"] is False
    assert bad["unmapped_delta_failure_ids"] == ["unknown"]


def test_scar_delta_distinctness_fails_closed_on_missing_ids() -> None:
    receipt = repair.verify_delta_distinctness(
        failure_rows=[{"failure_id": None}, {"failure_id": "f2"}],
        delta_rows=[{"source_failure_id": ""}, {"source_failure_id": "f2"}],
        parent_adapter_hash="aaa",
        delta_adapter_hash="bbb",
    )

    assert receipt["identifiers_complete"] is False
    assert receipt["missing_failure_id_rows"] == [0]
    assert receipt["missing_delta_source_id_rows"] == [0]
    assert receipt["scar_learning_claim_allowed"] is False
    assert "None" not in receipt["observed_failures_without_delta_examples"]
    assert "None" not in receipt["unmapped_delta_failure_ids"]


def test_no_scar_learning_claim_without_distinct_delta(tmp_path: Path) -> None:
    _stage(tmp_path)
    schema = _load(tmp_path / repair.ARTIFACTS["delta_distinct_hash_schema"])
    assert schema["properties"]["delta_adapter_hash_distinct"]["const"] is True


def test_expanded_benchmark_requires_route_regret_leakage_and_evaluator_integrity(tmp_path: Path) -> None:
    _stage(tmp_path)
    config = _load(tmp_path / repair.ARTIFACTS["expanded_benchmark_config"])

    assert config["sample_count_per_dataset"] == 50
    assert config["route_regret_required"] is True
    assert config["verified_work_per_token_required"] is True
    assert config["benchmark_leakage_scan_required"] is True
    assert config["evaluator_integrity_receipt_required"] is True


def test_kaggle_packet_is_one_cell_compatible_and_head_bound(tmp_path: Path) -> None:
    _stage(tmp_path)
    packet_zip = tmp_path / repair.ARTIFACTS["packet_zip"]
    manifest = _load(tmp_path / repair.ARTIFACTS["packet_manifest"])
    inspection = _load(tmp_path / repair.ARTIFACTS["inspection_receipt"])

    assert packet_zip.is_file()
    assert manifest["one_cell_kaggle_compatible"] is True
    assert manifest["head_binding_required"] is True
    assert manifest["runtime_requested_head_default"] == "ACTUAL_GIT_HEAD"
    assert manifest["packet_build_head_recorded"] is True
    assert inspection["compute_packet_sha256"] == sha256(packet_zip.read_bytes()).hexdigest()
    with zipfile.ZipFile(packet_zip, "r") as zf:
        names = set(zf.namelist())
    assert {
        "KT13_EXPAND_REPAIR_V1_RUNNER.py",
        "KAGGLE_BOOTSTRAP_CELL.py",
        "README_RUNBOOK.md",
        "PACKET_MANIFEST.json",
        "SHA256_MANIFEST.json",
    }.issubset(names)


def test_kaggle_runner_fails_closed_on_unknown_head_and_pending_receipts(tmp_path: Path) -> None:
    _stage(tmp_path)
    runner = (tmp_path / repair.ARTIFACTS["packet_runner"]).read_text(encoding="utf-8")

    assert 'PACKET_BUILD_HEAD = "' in runner
    assert "REQUESTED_HEAD_ENV = os.environ.get(\"KT_REQUESTED_HEAD\")" in runner
    assert "if REQUESTED_HEAD_ENV is not None" in runner
    assert "return \"\", \"KT_REQUESTED_HEAD_ENV_EMPTY\"" in runner
    assert "REQUESTED_HEAD_EMPTY" in runner
    assert "return actual_head, \"ACTUAL_GIT_HEAD_DEFAULT\"" in runner
    assert "packet_build_head_is_ancestor_of_actual" in runner
    assert "head_match = actual_head_known and actual_head == requested" in runner
    assert '"HEAD_UNKNOWN" if not actual_head_known else "HEAD_MISMATCH"' in runner
    assert '"evaluator_integrity_status": "PENDING_EXECUTION"' in runner
    assert '"leakage_scan_status": "PENDING_EXECUTION"' in runner
    assert '"evaluator_integrity_pass": True' not in runner
    assert '"leakage_scan_pass": True' not in runner


def test_kaggle_bootstrap_uses_safe_extract_and_packet_disambiguation(tmp_path: Path) -> None:
    _stage(tmp_path)
    bootstrap = (tmp_path / repair.ARTIFACTS["packet_bootstrap"]).read_text(encoding="utf-8")

    assert "def _safe_extract" in bootstrap
    assert "Unsafe zip member path" in bootstrap
    assert "KT_PACKET_ZIP_PATH" in bootstrap
    assert "KT_PACKET_SHA256" in bootstrap
    assert "KT_REQUESTED_HEAD" not in bootstrap
    assert "Multiple candidate packets found" in bootstrap
    assert 'namespace = {"__name__": "__kt_runner__"}' in bootstrap
    assert "raise SystemExit" not in bootstrap


def test_artifact_registry_delta_preserves_claim_ceiling(tmp_path: Path) -> None:
    _stage(tmp_path)
    delta = _load(tmp_path / repair.ARTIFACTS["artifact_delta"])
    registry = _load(tmp_path / repair.ARTIFACTS["artifact_registry"])
    artifact_ids = {artifact["artifact_id"] for artifact in registry["artifacts"]}

    assert "KT_HAT_MODE_CONTRACT" in artifact_ids
    assert "KT13_EXPAND_REPAIR_PACKET" in artifact_ids
    assert delta["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    for key, expected in repair.BLOCKED_CLAIMS.items():
        assert delta[key] is expected
