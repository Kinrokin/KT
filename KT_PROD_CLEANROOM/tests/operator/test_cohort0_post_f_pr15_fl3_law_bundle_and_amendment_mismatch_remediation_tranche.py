from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_remediation_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_t01_remediation_packet_repairs_support_chain_without_widening_scope(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        {"schema_id": "authority-packet", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        {"schema_id": "authority-receipt", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet.json",
        {"schema_id": "t01-packet", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
        {
            "schema_id": "t01-receipt",
            "status": "PASS",
            "next_lawful_move": "EXECUTE_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REMEDIATION",
        },
    )

    change_receipt = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_CHANGE_RECEIPT_FL3_TEST.json"
    change_receipt.parent.mkdir(parents=True, exist_ok=True)
    change_receipt.write_text("{}\n", encoding="utf-8")
    amendment = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_AMENDMENT_FL3_TEST.json"
    amendment.write_text("{}\n", encoding="utf-8")
    kt_cli = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator" / "kt_cli.py"
    kt_cli.parent.mkdir(parents=True, exist_ok=True)
    kt_cli.write_text("", encoding="utf-8")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(tranche, "_require_hmac_keys", lambda: {"SIGNER_A": "KT_HMAC_KEY_SIGNER_A", "SIGNER_B": "KT_HMAC_KEY_SIGNER_B"})
    monkeypatch.setattr(tranche, "_compute_current_bundle_hash", lambda root: "905ab6")
    monkeypatch.setattr(tranche, "_read_sha_pin", lambda root: "375558")
    monkeypatch.setattr(tranche, "_find_supported_old_ref", lambda root, current_hash, pinned_hash: ("old-ref", "375558"))
    monkeypatch.setattr(tranche, "_sync_law_bundle_sha", lambda root, new_hash: ("375558", "905ab6"))
    monkeypatch.setattr(tranche, "_mint_change_receipt", lambda root, old_ref: change_receipt)
    monkeypatch.setattr(tranche, "_ensure_law_amendment_hmac", lambda root, bundle_hash: amendment)
    monkeypatch.setattr(tranche, "_update_kt_cli_support_chain", lambda root, new_bundle_hash, new_change_receipt_rel: None)

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        t01_packet_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet.json",
        t01_receipt_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["mapping"]["resolution_class"] == "BIND_SUPERSESSION_AND_AMENDMENT_MAPPING"
    assert packet["mapping"]["old_supported_ref"] == "old-ref"
    assert packet["mapping"]["new_active_tree_hash"] == "905ab6"
    assert packet["success_condition"]["current_hash_has_law_amendment_v2"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
