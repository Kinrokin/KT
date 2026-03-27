from __future__ import annotations

import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _common_args(tmp_path: Path) -> list[str]:
    return [
        "--commercial-truth-output",
        str(tmp_path / "commercial_truth.json"),
        "--public-verifier-kit-output",
        str(tmp_path / "public_verifier_kit.json"),
        "--second-host-kit-output",
        str(tmp_path / "second_host_kit.json"),
        "--external-audit-output",
        str(tmp_path / "external_audit_packet.json"),
        "--receipt-output",
        str(tmp_path / "receipt.json"),
    ]


def _load_e1(root: Path):
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM"))
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))
    from tools.operator import e1_bounded_campaign_validate as e1

    return e1


def _patch_write_scope(monkeypatch, e1) -> None:
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


def test_t10_receipt_final_head_authority_alignment_passes_on_current_repo() -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    generated_utc = "2026-03-27T18:38:43Z"
    t7 = e1.build_comparator_side_reader_contract_adoption_receipt(root=root)
    t8 = e1.build_side_reader_receipt_refresh_scope_receipt(root=root, generated_utc=generated_utc, side_reader_contract_receipt=t7)
    t9 = e1.build_side_reader_refresh_caller_isolation_receipt(
        root=root,
        generated_utc=generated_utc,
        side_reader_contract_receipt=t7,
        side_reader_refresh_scope_receipt=t8,
    )
    t10 = e1.build_side_reader_refresh_indirection_barrier_receipt(
        root=root,
        generated_utc=generated_utc,
        side_reader_contract_receipt=t7,
        side_reader_refresh_scope_receipt=t8,
        side_reader_refresh_caller_isolation_receipt=t9,
    )

    result = e1.build_t10_receipt_final_head_authority_alignment_receipt(
        root=root,
        generated_utc=generated_utc,
        side_reader_contract_receipt=t7,
        side_reader_refresh_scope_receipt=t8,
        side_reader_refresh_caller_isolation_receipt=t9,
        side_reader_refresh_indirection_barrier_receipt=t10,
    )

    assert result["status"] == "PASS"
    assert result["tracked_t10_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert result["tracked_t10_contract"]["blocked"] is True
    assert result["tracked_t10_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert result["authoritative_current_head_t10_candidate_contract"]["pass"] is True
    assert result["authoritative_current_head_t10_candidate_contract"]["subject_head"] == result["current_git_head"]


def test_t11_receipt_requires_explicit_dual_opt_in(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)

    try:
        e1.main(
            [
                *_common_args(tmp_path),
                "--t10-receipt-final-head-authority-alignment-output",
                str(tmp_path / "t10_receipt_final_head_authority_alignment_receipt.json"),
            ]
        )
    except RuntimeError as exc:
        assert "FAIL_CLOSED: T11 final-head authority alignment receipt requires explicit dual-opt-in verification-only refresh" in str(exc)
    else:
        raise AssertionError("expected fail-closed T11 receipt gating error")


def test_dual_opt_in_can_emit_t11_receipt_when_explicitly_requested(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)
    t11_receipt = tmp_path / "t10_receipt_final_head_authority_alignment_receipt.json"

    result = e1.main(
        [
            *_common_args(tmp_path),
            "--allow-side-reader-contract-receipt-refresh",
            "--verification-only-side-reader-receipt-refresh",
            "--t10-receipt-final-head-authority-alignment-output",
            str(t11_receipt),
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["side_reader_receipt_refresh_enabled"] is True
    assert payload["t10_receipt_final_head_authority_alignment_status"] == "PASS"

    receipt = json.loads(t11_receipt.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T11_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
    assert receipt["tracked_t10_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    checks = {check["check_id"]: check["pass"] for check in receipt["checks"]}
    assert checks["tracked_t10_overread_fails_closed"] is True
    assert checks["tracked_t10_classified_documentary_carrier_only"] is True
    assert checks["authoritative_final_head_requires_matching_subject_head"] is True
