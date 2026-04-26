from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_post_boundary_canonical_regrade_audit_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base_receipt(schema: str = "receipt") -> dict:
    return {
        "schema_id": schema,
        "status": "PASS",
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
    }


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical", "status": "ACTIVE"})
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "ACTIVE"})
    _write_json(
        reports / tranche.POST_MERGE_CLOSEOUT,
        {
            **_base_receipt("post_merge"),
            "next_lawful_move": "RUN_POST_BOUNDARY_CANONICAL_REGRADE_AUDIT",
            "unknown_zone_queue_count": 0,
            "live_blocker_count": 0,
            "post_merge_validation": {
                "trust_zone_validation_status": "PASS",
                "trust_zone_validation_check_count": 24,
                "trust_zone_validation_failure_count": 0,
            },
        },
    )
    _write_json(reports / tranche.TRUTH_ENGINE_HANDOFF, {**_base_receipt("truth_handoff"), "blocking_contradiction_count": 0})
    _write_json(
        reports / tranche.TRUTH_ENGINE_CONTRADICTION_LEDGER,
        {**_base_receipt("truth_ledger"), "blocking_contradiction_count": 0, "advisory_contradiction_count": 0},
    )
    for filename in [
        tranche.TRACK_01_FINAL,
        tranche.TRACK_02_FINAL,
        tranche.TRACK_03_FINAL,
        tranche.TRACK_03_POST_MERGE,
        tranche.PR15_FL3_CLOSEOUT,
    ]:
        _write_json(reports / filename, _base_receipt(filename))
    _write_json(
        reports / tranche.UNKNOWN_QUEUE,
        {**_base_receipt("unknown_queue"), "queue_count": 0, "live_blocker_count": 0},
    )
    _write_json(
        reports / tranche.REMAINING_UNKNOWN_LEDGER,
        {**_base_receipt("remaining_unknown"), "remaining_unknown_count": 0, "live_blocker_count": 0},
    )
    _write_json(
        reports / tranche.PRODUCT_PROOF_REVIEW,
        {
            **_base_receipt("product_review"),
            "finding_count": 6,
            "resolved_count": 2,
            "deferred_count": 4,
            "live_blocker_count": 0,
            "decisions": [
                {"decision": "RESOLVED", "may_drive_product_truth": False},
                {"decision": "DEFERRED", "may_drive_product_truth": False},
            ],
        },
    )
    _write_json(
        reports / tranche.TRUST_ZONE_VALIDATION_MATRIX,
        {**_base_receipt("validation"), "validation_status": "PASS", "check_count": 24, "failure_count": 0},
    )
    return reports, governance


def test_post_boundary_regrade_emits_audit_ledgers_and_recommendation(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []})

    result = tranche.run(reports_root=reports, governance_root=governance)

    assert result["outcome"] == tranche.OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    weakness = _load(reports / tranche.WEAKNESS_LEDGER)
    gaps = _load(reports / tranche.A_PLUS_GAP_LEDGER)
    recommendation = _load(reports / tranche.NEXT_LANE_RECOMMENDATION)

    assert receipt["unknown_zone_queue_count"] == 0
    assert receipt["truth_engine_blocking_contradictions"] == 0
    assert receipt["product_proof_deferred_non_authoritative"] == 4
    assert receipt["recommended_next_authoritative_lane"] == "upper_stack_ratification_readiness"
    assert weakness["closed_or_strongly_contained_count"] == 5
    assert gaps["open_gap_count"] == 5
    assert recommendation["recommended_next_move"] == tranche.NEXT_MOVE


def test_post_boundary_regrade_hashes_evidence_independent_of_cwd(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []})
    monkeypatch.chdir(tmp_path / "KT_PROD_CLEANROOM")

    result = tranche.run(reports_root=reports, governance_root=governance)

    packet = _load(reports / tranche.OUTPUT_PACKET)
    assert result["outcome"] == tranche.OUTCOME
    assert packet["evidence_refs"]["post_merge_closeout"]["path"] == f"KT_PROD_CLEANROOM/reports/{tranche.POST_MERGE_CLOSEOUT}"
    assert len(packet["evidence_refs"]["post_merge_closeout"]["sha256"]) == 64


def test_post_boundary_regrade_fails_if_package_promotion_not_deferred(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    closeout = _load(reports / tranche.POST_MERGE_CLOSEOUT)
    closeout["package_promotion_remains_deferred"] = False
    _write_json(reports / tranche.POST_MERGE_CLOSEOUT, closeout)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []})

    with pytest.raises(RuntimeError, match="package_promotion_remains_deferred"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_post_boundary_regrade_fails_on_unknown_zone_regression(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    unknown = _load(reports / tranche.UNKNOWN_QUEUE)
    unknown["queue_count"] = 1
    _write_json(reports / tranche.UNKNOWN_QUEUE, unknown)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []})

    with pytest.raises(RuntimeError, match="queue_count=0"):
        tranche.run(reports_root=reports, governance_root=governance)
