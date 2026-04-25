from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_parallel_trust_zone_boundary_purification_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_trust_zone_boundary_purification_packet_stays_prep_only(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json", {"schema_id": "a", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_truth_engine_recompute_receipt.json", {"schema_id": "b", "status": "PASS"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json",
        recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
    )
    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    assert "KT_PROD_CLEANROOM/runs/post_f_track_03/**" in packet["noncanonical_quarantine_candidate_list_v2"]["candidates"]

