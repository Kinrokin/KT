from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.authority_topology_cutover_validate import build_authority_topology_cutover_outputs


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_ws6_repo(root: Path) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/documentary_truth_policy.json",
        {
            "active_current_head_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
            "active_supporting_truth_surfaces": [
                "kt_truth_ledger:ledger/current/current_state_receipt.json",
                "kt_truth_ledger:ledger/current/runtime_closure_audit.json",
            ],
            "documentary_only_refs": [
                "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
                "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
            ],
            "documentary_only_patterns": ["docs/**"],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/execution_board.json",
        {
            "authoritative_current_head_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
            "authoritative_truth_sources": [
                "kt_truth_ledger:ledger/current/current_state_receipt.json",
                "kt_truth_ledger:ledger/current/runtime_closure_audit.json",
            ],
            "authority_mode": "TRANSITIONAL_AUTHORITATIVE",
            "DOCUMENTARY_ONLY": True,
            "LIVE_TRUTH_ALLOWED": False,
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
        {
            "authoritative_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
            "current_authority_mode": "TRANSITIONAL_AUTHORITATIVE",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json",
        {"current_head_truth_root": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json",
        {"current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json",
        {"required_outputs": ["kt_truth_ledger:ledger/current/current_pointer.json"]},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json",
        {"current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json",
        {
            "generated_authoritative_surfaces": [
                "kt_truth_ledger:ledger/current/current_pointer.json",
                "kt_truth_ledger:ledger/current/current_bundle_manifest.json",
                "kt_truth_ledger:ledger/bundles/**",
            ],
            "tracked_documentary_surfaces": [
                "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
                "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
            ],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
        {
            "generated_truth_surfaces": [
                "kt_truth_ledger:ledger/current/current_pointer.json",
                "kt_truth_ledger:ledger/current/current_state_receipt.json",
                "kt_truth_ledger:ledger/current/runtime_closure_audit.json",
            ]
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/public_verifier_rules.json",
        {"authority_refs": ["kt_truth_ledger:ledger/current/current_pointer.json"]},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/external_legibility_contract.json",
        {"authority_refs": ["kt_truth_ledger:ledger/current/current_pointer.json"]},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        {"truth_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(root / "ledger/current/current_pointer.json", {"status": "ACTIVE"})
    _write_json(root / "ledger/current/current_state_receipt.json", {"status": "TRANSITIONAL"})
    _write_json(root / "ledger/current/runtime_closure_audit.json", {"status": "TRANSITIONAL"})
    _write_json(
        root / "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        {"documentary_only": True, "live_authority": False, "mirror_class": "documentary_compatibility_surface", "superseded_by": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
        {"documentary_only": True, "live_authority": False, "mirror_class": "documentary_compatibility_surface", "superseded_by": ["kt_truth_ledger:ledger/current/current_pointer.json", "kt_truth_ledger:ledger/current/current_state_receipt.json"]},
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
        {"documentary_only": True, "live_authority": False, "mirror_class": "documentary_compatibility_surface", "superseded_by": ["kt_truth_ledger:ledger/current/current_pointer.json", "kt_truth_ledger:ledger/current/runtime_closure_audit.json"]},
    )


def test_authority_topology_cutover_passes_when_ledger_is_sole_live_source(tmp_path: Path) -> None:
    _seed_ws6_repo(tmp_path)
    documentary, demotion, cutover = build_authority_topology_cutover_outputs(root=tmp_path)
    assert documentary["status"] == "PASS", documentary
    assert demotion["status"] == "PASS", demotion
    assert cutover["status"] == "PASS", cutover
    assert cutover["pass_verdict"] == "LEDGER_AUTHORITY_FINALIZED"


def test_authority_topology_cutover_fails_when_board_keeps_repo_mirror_live(tmp_path: Path) -> None:
    _seed_ws6_repo(tmp_path)
    board_path = tmp_path / "KT_PROD_CLEANROOM/governance/execution_board.json"
    board = json.loads(board_path.read_text(encoding="utf-8"))
    board["authoritative_current_head_truth_source"] = "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
    board_path.write_text(json.dumps(board, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    documentary, demotion, cutover = build_authority_topology_cutover_outputs(root=tmp_path)
    assert documentary["status"] == "FAIL"
    assert demotion["status"] == "PASS"
    assert cutover["status"] == "FAIL_CLOSED"
    assert "execution_board_points_to_ledger_pointer" in cutover["issues_found"]
