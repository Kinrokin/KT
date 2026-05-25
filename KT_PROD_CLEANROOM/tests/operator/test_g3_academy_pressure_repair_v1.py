from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path
import pytest

from tools.operator import g3_academy_pressure_repair_v1 as g3


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_registry(tmp_path: Path) -> None:
    root = g3.repo_root()
    target = tmp_path / "registry" / "artifact_authority_registry.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "registry" / "artifact_authority_registry.json", target)


def _sample_predictions() -> list[dict]:
    rows = []
    subjects = ["base_raw", "base_kt_hat_compact", "routed_13_lobe_raw", "routed_13_lobe_kt_hat_compact"]
    for dataset in ["gsm8k", "arc_challenge", "hellaswag", "truthfulqa_mc"]:
        for index in range(5):
            item_id = f"{dataset}-{index}"
            for subject in subjects:
                routed = subject == "routed_13_lobe_kt_hat_compact"
                base_raw = subject == "base_raw"
                correct = (index % 2 == 0) if routed else (base_raw or index % 3 == 0)
                rows.append(
                    {
                        "correct": correct,
                        "dataset": dataset,
                        "extraction_ok": True,
                        "item_id": item_id,
                        "kt_hat_compact": "compact" in subject,
                        "latency_seconds": 1.0 + index,
                        "new_tokens": 2 if "compact" in subject else 96,
                        "normalized_answer": str(index + 10),
                        "normalized_prediction": str(index + 10 if correct else index),
                        "raw_prediction": str(index + 10 if correct else index),
                        "route_adapter": g3._target_lobe_for_dataset(dataset, None) if routed else None,
                        "subject": subject,
                    }
                )
    return rows


def _sample_scorecard() -> dict:
    return {
        "schema_id": "kt.g2.benchmark_scorecard.v2",
        "by_subject": {
            "base_raw": {"accuracy": 0.6, "correct": 12, "count": 20, "tokens": 500, "tokens_per_correct": 42.0},
            "base_kt_hat_compact": {"accuracy": 0.62, "correct": 13, "count": 20, "tokens": 50, "tokens_per_correct": 3.8},
            "routed_13_lobe_raw": {"accuracy": 0.55, "correct": 11, "count": 20, "tokens": 500, "tokens_per_correct": 45.0},
            "routed_13_lobe_kt_hat_compact": {"accuracy": 0.65, "correct": 13, "count": 20, "tokens": 49, "tokens_per_correct": 3.7},
        },
        "by_subject_dataset": {},
    }


def _sample_route_regret() -> dict:
    rows = []
    for dataset in ["gsm8k", "arc_challenge", "hellaswag", "truthfulqa_mc"]:
        for index in range(5):
            rows.append(
                {
                    "best_correct": True,
                    "best_route_adapter": None,
                    "best_subject_in_hindsight": "base_raw" if index % 2 else "routed_13_lobe_kt_hat_compact",
                    "chosen_correct": index % 2 == 0,
                    "chosen_route_adapter": g3._target_lobe_for_dataset(dataset, None),
                    "chosen_subject": "routed_13_lobe_kt_hat_compact",
                    "correctness_delta": 1 if index % 2 else 0,
                    "dataset": dataset,
                    "item_id": f"{dataset}-{index}",
                    "latency_delta": 0.1,
                    "token_delta": 0,
                }
            )
    return {"schema_id": "kt.g2.route_regret_matrix.v2", "sample_count": len(rows), "rows": rows}


def _make_g2_zip(tmp_path: Path) -> Path:
    predictions = _sample_predictions()
    summary = {
        "schema_id": "kt.g2.assessment_summary.v2",
        "actual_head": "test-head",
        "adapter_store": "test-adapter-store",
        "base_model": "test-base",
        "claim_ceiling": dict(g3.BLOCKED_CLAIMS),
        "outcome": "KT_G2_EXPANDED_DETACHED_BENCHMARK_COMPLETE__G3_DECISION_READY__CLAIM_CEILING_PRESERVED",
        "prediction_rows": len(predictions),
        "summary": _sample_scorecard(),
    }
    zip_path = tmp_path / "g2_assessment.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("outputs/reports/assessment_summary.json", json.dumps(summary, sort_keys=True))
        zf.writestr("outputs/reports/benchmark_scorecard.json", json.dumps(_sample_scorecard(), sort_keys=True))
        zf.writestr("outputs/reports/verified_work_per_token_scorecard.json", json.dumps(_sample_scorecard(), sort_keys=True))
        zf.writestr("outputs/reports/route_regret_matrix.json", json.dumps(_sample_route_regret(), sort_keys=True))
        zf.writestr("outputs/reports/dataset_load_receipt.json", json.dumps({"schema_id": "kt.g2.dataset_load_receipt.v2"}))
        zf.writestr(
            "outputs/reports/benchmark_predictions.jsonl",
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in predictions),
        )
    return zip_path


def _stage(tmp_path: Path) -> dict:
    _copy_registry(tmp_path)
    return g3.run(output_root=tmp_path, g2_evidence_path=str(_make_g2_zip(tmp_path)))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_g3_imports_real_g2_evidence_and_emits_ready_packet(tmp_path: Path) -> None:
    summary = _stage(tmp_path)
    receipt = _load(tmp_path / g3.ARTIFACTS["final_receipt"])
    import_receipt = _load(tmp_path / g3.ARTIFACTS["g2_evidence_import_receipt"])

    assert summary["outcome"] == g3.TARGET_OUTCOME
    assert summary["next_lawful_move"] == g3.NEXT_LAWFUL_MOVE
    assert import_receipt["g2_evidence_imported"] is True
    assert import_receipt["prompt_stated_numbers_used_as_evidence"] is False
    assert receipt["claim_ceiling_status"] == "UNCHANGED"
    packet_zip = tmp_path / g3.ARTIFACTS["packet_zip"]
    assert packet_zip.is_file()
    with zipfile.ZipFile(packet_zip) as zf:
        names = set(zf.namelist())
    assert {
        "G2_FAILURE_MAP.json",
        "G2_ROUTE_REGRET_TARGETS.json",
        "HUMAN_ANCHOR_MANIFEST.json",
        "G3_MATH_REPAIR_CORPUS.jsonl",
        "G3_KT_HAT_CALIBRATION_CORPUS.jsonl",
    }.issubset(names)


def test_g3_failure_map_and_route_regret_are_source_bound(tmp_path: Path) -> None:
    _stage(tmp_path)
    failure_map = _load(tmp_path / g3.ARTIFACTS["g2_failure_map"])
    targets = _load(tmp_path / g3.ARTIFACTS["g2_route_regret_targets"])

    assert failure_map["failure_count"] > 0
    assert targets["target_count"] > 0
    assert all(row["failure_id"].startswith("G2::") for row in failure_map["rows"])
    assert all(row["target_lobe"] in g3.CANONICAL_LOBES for row in failure_map["rows"])
    assert any("FORMAL_MATH_FINAL_ANSWER_REPAIR_TARGET" in row["failure_modes"] for row in failure_map["rows"])


def test_g3_metric_constitution_pairs_every_metric_with_anti_goodhart_guard(tmp_path: Path) -> None:
    _stage(tmp_path)
    constitution = _load(tmp_path / g3.ARTIFACTS["g3_metric_constitution"])
    scorecard = _load(tmp_path / g3.ARTIFACTS["anti_goodhart_scorecard"])

    assert constitution["anti_goodhart_pairing_complete"] is True
    assert scorecard["anti_goodhart_pairing_complete"] is True
    for metric in constitution["metrics"]:
        assert metric["goodhart_failure_mode"]
        assert metric["anti_goodhart_pair"]


def test_g3_human_anchor_manifest_blocks_metric_collapse(tmp_path: Path) -> None:
    _stage(tmp_path)
    manifest = _load(tmp_path / g3.ARTIFACTS["human_anchor_manifest"])
    receipt = _load(tmp_path / g3.ARTIFACTS["human_anchor_anti_collapse_receipt"])

    assert manifest["human_anchor_pass"] is True
    assert manifest["anchor_ratio"] >= manifest["minimum_anchor_ratio_required"]
    assert receipt["metric_collapse_blocked"] is True
    assert all(anchor["gold_normalized_answer"] is not None for anchor in manifest["anchors"])


def test_g3_build_vs_run_boundary_and_no_placeholder_pass(tmp_path: Path) -> None:
    _stage(tmp_path)
    boundary = _load(tmp_path / g3.ARTIFACTS["build_vs_run_boundary_receipt"])
    no_placeholder = _load(tmp_path / g3.ARTIFACTS["no_placeholder_pass_receipt"])
    manifest = _load(tmp_path / g3.ARTIFACTS["packet_manifest"])

    assert boundary["mode"] == "BUILD"
    assert boundary["kaggle_run_executed"] is False
    assert boundary["trained_weights_created"] is False
    assert no_placeholder["no_placeholder_pass"] is True
    assert manifest["one_cell_kaggle_compatible"] is True
    assert manifest["claims_authorized"] == []
    bootstrap = (tmp_path / g3.ARTIFACTS["packet_bootstrap"]).read_text(encoding="utf-8")
    assert "KT_PACKET_ZIP_PATH" in bootstrap
    assert "KT_PACKET_SHA256" in bootstrap
    assert "Multiple candidate packets found" in bootstrap
    assert "root in target.parents" in bootstrap
    assert "str(target).startswith" not in bootstrap


def test_g3_discovery_rejects_unsupported_manifest_candidate(tmp_path: Path) -> None:
    manifest = tmp_path / "reports" / "g2_evidence_manifest.json"
    _write_json(manifest, {"schema_id": "kt.g3.g2_evidence_manifest.v1"})

    with pytest.raises(FileNotFoundError):
        g3.discover_g2_evidence(tmp_path, str(manifest))


def test_g3_registry_delta_preserves_claim_ceiling(tmp_path: Path) -> None:
    _stage(tmp_path)
    registry = _load(tmp_path / g3.ARTIFACTS["artifact_registry"])
    delta = _load(tmp_path / g3.ARTIFACTS["artifact_delta"])
    ids = {artifact["artifact_id"] for artifact in registry["artifacts"]}

    assert "KT_G3_G2_EVIDENCE_MANIFEST" in ids
    assert "KTG3_TARGETED_RUN_PACKET" in ids
    assert delta["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    for key, expected in g3.BLOCKED_CLAIMS.items():
        assert delta[key] is expected
