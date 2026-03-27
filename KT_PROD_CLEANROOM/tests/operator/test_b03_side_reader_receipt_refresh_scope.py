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


def test_side_reader_receipt_refresh_requires_dual_opt_in(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)

    try:
        e1.main(
            [
                *_common_args(tmp_path),
                "--allow-side-reader-contract-receipt-refresh",
                "--side-reader-contract-receipt-output",
                str(tmp_path / "comparator_side_reader_contract_adoption_receipt.json"),
            ]
        )
    except RuntimeError as exc:
        assert "FAIL_CLOSED: side-reader contract receipt refresh requires both" in str(exc)
    else:
        raise AssertionError("expected fail-closed dual-opt-in error")


def test_custom_side_reader_receipt_output_without_flags_fails_closed(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)

    try:
        e1.main(
            [
                *_common_args(tmp_path),
                "--side-reader-contract-receipt-output",
                str(tmp_path / "comparator_side_reader_contract_adoption_receipt.json"),
            ]
        )
    except RuntimeError as exc:
        assert "FAIL_CLOSED: side-reader contract receipt refresh requires both" in str(exc)
    else:
        raise AssertionError("expected fail-closed custom-output error")


def test_dual_opt_in_verification_only_refresh_emits_t8_receipt(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)
    side_reader_receipt = tmp_path / "comparator_side_reader_contract_adoption_receipt.json"
    refresh_scope_receipt = tmp_path / "side_reader_receipt_refresh_scope_receipt.json"

    result = e1.main(
        [
            *_common_args(tmp_path),
            "--allow-side-reader-contract-receipt-refresh",
            "--verification-only-side-reader-receipt-refresh",
            "--side-reader-contract-receipt-output",
            str(side_reader_receipt),
            "--side-reader-refresh-scope-receipt-output",
            str(refresh_scope_receipt),
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["side_reader_receipt_refresh_enabled"] is True

    t7_receipt = json.loads(side_reader_receipt.read_text(encoding="utf-8"))
    t8_receipt = json.loads(refresh_scope_receipt.read_text(encoding="utf-8"))
    assert t7_receipt["receipt_role"] == "COUNTED_T7_SIDE_READER_CONTRACT_ADOPTION_ARTIFACT_ONLY"
    assert t8_receipt["status"] == "PASS"
    assert t8_receipt["receipt_role"] == "COUNTED_T8_REFRESH_SCOPE_HARDENING_ARTIFACT_ONLY"
    checks = {check["check_id"]: check["pass"] for check in t8_receipt["checks"]}
    assert checks["default_path_does_not_enable_refresh"] is True
    assert checks["dual_opt_in_default_target_enables_refresh"] is True
    assert checks["verification_only_refresh_preserves_t7_contract"] is True
