from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.watcher_spc_validators import (  # noqa: E402
    WatcherSPCValidationError,
    assert_runtime_registry_has_no_watcher_spc,
    validate_watcher_spc_artifacts_if_present,
)


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def test_watcher_spc_absent_is_noop(tmp_path: Path) -> None:
    validate_watcher_spc_artifacts_if_present(evidence_dir=tmp_path)


def test_watcher_spc_malformed_provenance_fails_closed(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "drift_map.json",
        {"scores": [{"score": 1.0, "evidence": [{"weight": 1.0, "pointer": {"transcript_relpath": "t.jsonl"}}]}]},
    )
    with pytest.raises(WatcherSPCValidationError):
        validate_watcher_spc_artifacts_if_present(evidence_dir=tmp_path)


def test_watcher_spc_monotone_score_validation(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "drift_map.json",
        {
            "scores": [
                {
                    "score": 3.0,
                    "evidence": [
                        {
                            "weight": 1.0,
                            "pointer": {
                                "transcript_relpath": "transcript.jsonl",
                                "start_line": 1,
                                "end_line": 2,
                                "line_hashes": ["a" * 64],
                                "edge_ids": ["e1"],
                            },
                        },
                        {
                            "weight": 2.0,
                            "pointer": {
                                "transcript_relpath": "transcript.jsonl",
                                "start_line": 3,
                                "end_line": 3,
                                "line_hashes": ["b" * 64],
                                "edge_ids": [],
                            },
                        },
                    ],
                }
            ]
        },
    )
    validate_watcher_spc_artifacts_if_present(evidence_dir=tmp_path)


def test_watcher_spc_score_must_equal_sum_weights(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "drift_map.json",
        {
            "scores": [
                {
                    "score": 999.0,
                    "evidence": [
                        {
                            "weight": 1.0,
                            "pointer": {
                                "transcript_relpath": "transcript.jsonl",
                                "start_line": 1,
                                "end_line": 1,
                                "line_hashes": ["a" * 64],
                                "edge_ids": [],
                            },
                        }
                    ],
                }
            ]
        },
    )
    with pytest.raises(WatcherSPCValidationError):
        validate_watcher_spc_artifacts_if_present(evidence_dir=tmp_path)


def test_spc_probe_candidates_must_be_quarantined_and_non_gating(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "spc_report.json",
        {
            "scores": [],
            "spc_probe_candidates": [{"quarantined": True, "gating": True}],
        },
    )
    with pytest.raises(WatcherSPCValidationError):
        validate_watcher_spc_artifacts_if_present(evidence_dir=tmp_path)


def test_runtime_registry_guard_blocks_watcher_root(tmp_path: Path) -> None:
    p = tmp_path / "registry.json"
    _write_json(p, {"runtime_import_roots": ["core", "watcher"]})
    with pytest.raises(WatcherSPCValidationError):
        assert_runtime_registry_has_no_watcher_spc(registry_path=p)

