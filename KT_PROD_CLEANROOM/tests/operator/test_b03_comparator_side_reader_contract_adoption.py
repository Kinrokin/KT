from __future__ import annotations

import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_side_reader_contract_helpers_fail_closed_on_missing_and_mismatched_fields() -> None:
    root = _repo_root()
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM"))
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))

    from tools.operator import e1_bounded_campaign_validate as e1
    from tools.operator import final_current_head_adjudication_validate as final
    from tools.operator import w3_externality_and_comparative_proof_validate as w3

    for module in (e1, final, w3):
        result = module.evaluate_comparator_side_reader_contract(root=root)
        assert result["status"] == "PASS"
        assert result["legacy_parse_removed"] is True
        attempts = {attempt["attempt_id"]: attempt for attempt in result["malformed_attempts"]}
        assert attempts["missing_receipt_role"]["blocked"] is True
        assert attempts["missing_receipt_role"]["failure_reason"] == "RECEIPT_ROLE_MISSING"
        assert attempts["missing_subject_head"]["blocked"] is True
        assert attempts["missing_subject_head"]["failure_reason"] == "SUBJECT_HEAD_MISSING"
        assert attempts["wrong_receipt_role"]["blocked"] is True
        assert attempts["wrong_receipt_role"]["failure_reason"] == "RECEIPT_ROLE_MISMATCH"
        assert attempts["wrong_subject_head"]["blocked"] is True
        assert attempts["wrong_subject_head"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"


def test_e1_cli_emits_side_reader_contract_adoption_receipt(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM"))
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))
    from tools.operator import e1_bounded_campaign_validate as e1

    monkeypatch.setattr(e1, "_enforce_write_scope_pre", lambda _root: [])
    monkeypatch.setattr(
        e1,
        "_enforce_write_scope_post",
        lambda _root, *, prewrite_dirty, allowed_repo_writes: {
            "prewrite_dirty_paths": list(prewrite_dirty),
            "postwrite_dirty_paths": list(prewrite_dirty),
            "allowed_repo_writes": list(allowed_repo_writes),
            "unexpected_postwrite_paths": [],
            "undeclared_created_paths": [],
        },
    )

    commercial_truth_path = tmp_path / "commercial_truth.json"
    verifier_kit_path = tmp_path / "public_verifier_kit.json"
    second_host_kit_path = tmp_path / "second_host_kit.json"
    external_audit_path = tmp_path / "external_audit_packet.json"
    receipt_path = tmp_path / "receipt.json"
    side_reader_contract_receipt_path = tmp_path / "comparator_side_reader_contract_adoption_receipt.json"
    side_reader_refresh_scope_receipt_path = tmp_path / "side_reader_receipt_refresh_scope_receipt.json"

    result = e1.main(
        [
            "--commercial-truth-output",
            str(commercial_truth_path),
            "--public-verifier-kit-output",
            str(verifier_kit_path),
            "--second-host-kit-output",
            str(second_host_kit_path),
            "--external-audit-output",
            str(external_audit_path),
            "--receipt-output",
            str(receipt_path),
            "--allow-side-reader-contract-receipt-refresh",
            "--verification-only-side-reader-receipt-refresh",
            "--side-reader-contract-receipt-output",
            str(side_reader_contract_receipt_path),
            "--side-reader-refresh-scope-receipt-output",
            str(side_reader_refresh_scope_receipt_path),
        ]
    )

    assert result == 0
    receipt = json.loads(side_reader_contract_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T7_SIDE_READER_CONTRACT_ADOPTION_ARTIFACT_ONLY"
    assert receipt["tranche_id"] == "B03_T7_COMPARATOR_SIDE_READER_CONTRACT_ADOPTION"
    assert all(result["status"] == "PASS" for result in receipt["reader_results"])
    refresh_scope_receipt = json.loads(side_reader_refresh_scope_receipt_path.read_text(encoding="utf-8"))
    assert refresh_scope_receipt["status"] == "PASS"
    assert refresh_scope_receipt["receipt_role"] == "COUNTED_T8_REFRESH_SCOPE_HARDENING_ARTIFACT_ONLY"
